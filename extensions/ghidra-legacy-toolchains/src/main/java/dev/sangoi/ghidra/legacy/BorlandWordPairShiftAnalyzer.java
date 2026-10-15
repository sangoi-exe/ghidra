package dev.sangoi.ghidra.legacy;

import java.util.Arrays;
import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** The complete original three-member family; no historical spelling or release is elected. */
public class BorlandWordPairShiftAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "Borland word-pair shifts (qualified 16-bit)";
    public static final String CONVENTION = "borland_word_shift_16far";
    private static final String MARKER = "[Qualified word-pair shift]";
    private static final String[] NAMES = { "left", "arithmetic_right", "logical_right" };
    private static final String[] BODIES = {
        "5b0e5380f91073108bd8d3e0d3e2f6d980c110d3eb0bd3cb80e9109233c0d3e2cb",
        "5b0e5380f91073108bdad3e8d3faf6d980c110d3e30bc3cb80e9109299d3f8cb",
        "5b0e5380f91073108bdad3e8d3eaf6d980c110d3e30bc3cb80e9109233d2d3e8cb"
    };
    private static final byte[] FAMILY = HexFormat.of().parseHex(String.join("", BODIES));
    private static final int[] OFFSETS = { 0, 33, 65 };
    private static final int[][] CORE_LENGTHS = {
        { 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 2, 2, 1 },
        { 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 1, 2, 1 },
        { 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 2, 2, 1 }
    };

    public BorlandWordPairShiftAnalyzer() {
        super(NAME, "Recognize all three complete DX:AX/CL shift bodies, retaining real near adapters and non-overlapping native far-core functions.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return new CoreContract(0).canAnalyze(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        for (var block : program.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            for (var range : new AddressSet(block.getStart(), block.getEnd()).intersect(set)) {
                Address next = range.getMinAddress();
                while (next != null && next.compareTo(range.getMaxAddress()) <= 0) {
                    monitor.checkCancelled();
                    Address match = program.getMemory().findBytes(next, range.getMaxAddress(), FAMILY, null, true, monitor);
                    if (match == null) {
                        break;
                    }
                    next = match.next();
                    if (match.add(FAMILY.length - 1).compareTo(block.getEnd()) > 0) {
                        continue;
                    }
                    try {
                        if (!qualifyInstructions(program, match, monitor)) {
                            log.appendMsg(NAME, "Complete family at " + match + " lacks qualified native 16-bit instruction boundaries");
                            continue;
                        }
                        for (int member = 0; member < NAMES.length; member++) {
                            Address near = match.add(OFFSETS[member]);
                            Address core = near.add(3);
                            AddressSet coreBody = new AddressSet(core, near.add(BODIES[member].length() / 2 - 1));
                            label(program, near, "qualified_word_shift_" + NAMES[member] + "_near_adapter");
                            label(program, core, "qualified_word_shift_" + NAMES[member] + "_far_core");
                            comment(program, near, MARKER + "\nReal near entry: POP BX; PUSH CS; PUSH BX. Converts the 2-byte near return IP to the core's 4-byte IP/CS return frame; BX becomes the original return IP. Falls through to " + core + ". Not a complete three-byte returning function; no near caller is inferred.");
                            comment(program, core, contractText(member) + "\nAlternate near entry at " + near + " falls through after constructing this far frame. Native function bodies cannot overlap; the adapter is labeled code, not a second prefix-only function.");
                            var owners = program.getFunctionManager().getFunctionsOverlapping(coreBody);
                            boolean conflict = false;
                            while (owners.hasNext()) {
                                Function owner = owners.next();
                                if (!owner.getEntryPoint().equals(core) || !owner.getBody().equals(coreBody)) {
                                    conflict = true;
                                    log.appendMsg(NAME, "Preserving native owner " + owner.getEntryPoint() + " " + owner.getBody() + "; exact far-core contract at " + core + " is blocked");
                                }
                            }
                            if (!conflict && !new CoreContract(member).added(program, coreBody, monitor, log)) {
                                return false;
                            }
                        }
                    }
                    catch (CancelledException e) {
                        throw e;
                    }
                    catch (Exception e) {
                        log.appendMsg(NAME, "Failed to annotate qualified family at " + match + ": " + e.getMessage());
                        log.appendException(e);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean qualifyInstructions(Program program, Address family, TaskMonitor monitor) {
        for (int member = 0; member < NAMES.length; member++) {
            Address near = family.add(OFFSETS[member]);
            Address end = near.add(BODIES[member].length() / 2 - 1);
            DisassembleCommand command = new DisassembleCommand(near, new AddressSet(near, end), true);
            command.enableCodeAnalysis(false);
            if (!command.applyTo(program, monitor)) {
                return false;
            }
            Address address = near;
            for (int index = 0; index < 3 + CORE_LENGTHS[member].length; index++) {
                int length = index < 3 ? 1 : CORE_LENGTHS[member][index - 3];
                var instruction = program.getListing().getInstructionAt(address);
                if (instruction == null || instruction.getLength() != length) {
                    return false;
                }
                for (String name : new String[] { "opsize", "addrsize" }) {
                    var value = program.getProgramContext().getValue(program.getRegister(name), address, false);
                    if (value == null || value.signum() != 0) {
                        return false;
                    }
                }
                address = address.add(length);
            }
        }
        return true;
    }

    private static void label(Program program, Address address, String name) throws Exception {
        if (program.getSymbolTable().getSymbol(name, address, null) == null) {
            program.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
        }
    }

    private static void comment(Program program, Address address, String text) {
        Function owner = program.getFunctionManager().getFunctionContaining(address);
        if (owner != null && owner.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
            return;
        }
        String previous = program.getListing().getComment(CommentType.PLATE, address);
        if (previous == null || !previous.contains(MARKER)) {
            program.getListing().setComment(address, CommentType.PLATE, previous == null || previous.isBlank() ? text : previous + "\n\n" + text);
        }
    }

    private static String contractText(int member) {
        String operation = switch (member) {
            case 0 -> "Finite 32-bit left shift modulo 2^32";
            case 1 -> "Finite signed 32-bit arithmetic right shift with sign fill";
            default -> "Finite unsigned 32-bit logical right shift with zero fill";
        };
        return MARKER + "\n" + operation + ", qualified only for entry CL in 0..31. DX:AX is both input and output; CL is an unsigned byte input, not CX.\n"
            + "Core has 15 instructions, three basic blocks, two plain RETF exits. No data argument purge; this entry consumes a 4-byte far return frame. No callfixup or replacement instruction semantics.\n"
            + "For entry count n<16, final CL=16-n; for 16<=n<=31, final CL=n-16. BX is scratch (unchanged by the core's high-count tail). Low16 BP/SI/DI/DS/ES and CH are not written; arithmetic flags are clobbered.\n"
            + "Counts outside 0..31 retain only original instruction mechanics: no clamp or universal mathematical pair-shift guarantee. This is not host-C undefined-shift behavior, a historical helper-name proof or a compiler/version election.";
    }

    /** Reuse the complete-body native contract path only for an exact non-overlapping far owner. */
    private static final class CoreContract extends QualifiedRuntimeHelperAnalyzer {
        private final int member;

        CoreContract(int member) {
            super(NAME, "Qualified far-core storage and frame contract", "qualified_word_shift_" + NAMES[member] + "_far_core", CONVENTION, "borland-word-shift-far.xml", Arrays.copyOfRange(HexFormat.of().parseHex(BODIES[member]), 3, BODIES[member].length() / 2), CORE_LENGTHS[member]);
            this.member = member;
        }

        @Override
        protected void applyContract(Program program, Function function) throws Exception {
            var pairType = member == 1 ? SignedDWordDataType.dataType : DWordDataType.dataType;
            VariableStorage pair = new VariableStorage(program, program.getRegister("DX"), program.getRegister("AX"));
            function.updateFunction(CONVENTION, new ReturnParameterImpl(pairType, pair, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
                new ParameterImpl("value", pairType, pair, program, SourceType.ANALYSIS),
                new ParameterImpl("count", ByteDataType.dataType, new VariableStorage(program, program.getRegister("CL")), program, SourceType.ANALYSIS));
            function.setStackPurgeSize(0);
            if (function.getSymbol().getSource() == SourceType.DEFAULT) {
                function.setName("qualified_word_shift_" + NAMES[member] + "_far_core", SourceType.ANALYSIS);
            }
            String previous = function.getComment();
            if (previous == null || !previous.contains(MARKER)) {
                function.setComment(previous == null || previous.isBlank() ? contractText(member) : previous + "\n\n" + contractText(member));
            }
        }
    }
}
