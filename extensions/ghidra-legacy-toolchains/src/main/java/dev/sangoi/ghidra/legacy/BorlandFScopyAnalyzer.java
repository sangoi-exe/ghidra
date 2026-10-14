package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Recognizes only the complete shared BCC 3.1/4.5 helper body, without identifying a compiler release. */
public class BorlandFScopyAnalyzer extends AbstractAnalyzer {
    public static final String CONVENTION = "borland_f_scopy_16far";
    public static final String NAME = "Borland F_SCOPY (qualified 16-bit)";

    private static final byte[] BODY = {
        0x55, (byte) 0x8b, (byte) 0xec, 0x56, 0x57, 0x1e, (byte) 0xc5, 0x76,
        0x06, (byte) 0xc4, 0x7e, 0x0a, (byte) 0xfc, (byte) 0xd1, (byte) 0xe9,
        (byte) 0xf3, (byte) 0xa5, 0x13, (byte) 0xc9, (byte) 0xf3, (byte) 0xa4,
        0x1f, 0x5f, 0x5e, 0x5d, (byte) 0xca, 0x08, 0x00
    };
    private static final int[] INSTRUCTION_LENGTHS = { 1, 2, 1, 1, 1, 3, 3, 1, 2, 2, 2, 2, 1, 1, 1, 1, 3 };
    private static final String COMMENT = "[Qualified Borland F_SCOPY]\n"
        + "Complete 28-byte body shared by supplied BCC 3.1 and 4.5 objects; no exclusive compiler identification.\n"
        + "Analysis inputs: CX = unsigned 16-bit byte count; source offset/selector at entry SP+4/+6; destination offset/selector at SP+8/+10.\n"
        + "FarAddress16 is an offset/selector storage record, not a recovered C type or proof of selector-to-address mapping.\n"
        + "RETF 8: 8 argument bytes purged, 4-byte far return, total entry-SP delta 12. No manufactured scalar return value; analysis void is not a historical C declaration.\n"
        + "On ordinary completion with valid, non-disruptive storage: BP/SI/DI/DS restored; AX/BX/DX untouched; SS not written; ES = destination selector; CX = 0; DF = 0.\n"
        + "Forward word copies then odd-byte tail; not memmove. Prototype clobbers ES/CX/DF but does not compute those post-call values or model copy memory effects.";

    public BorlandFScopyAnalyzer() {
        super(NAME, "Recognize the complete evidenced F_SCOPY body and apply its implicit CX and far-frame contract.", AnalyzerType.BYTE_ANALYZER);
        // Native SegmentedCallingConventionAnalyzer runs at LOW_PRIORITY and assigns a generic
        // convention from RETF alone, even when a function already has a named convention.
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        String language = program.getLanguageID().toString();
        return language.equals("x86:LE:16:Protected Mode") || language.equals("x86:LE:16:Real Mode");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        boolean installed = false;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            AddressSet search = new AddressSet(block.getStart(), block.getEnd()).intersect(set);
            for (var range : search) {
                Address next = range.getMinAddress();
                while (next != null && next.compareTo(range.getMaxAddress()) <= 0) {
                    monitor.checkCancelled();
                    Address match = program.getMemory().findBytes(next, range.getMaxAddress(), BODY, null, true, monitor);
                    if (match == null) {
                        break;
                    }
                    next = match.next();
                    Address end = match.add(BODY.length - 1);
                    if (end.compareTo(block.getEnd()) > 0) {
                        continue;
                    }
                    Function containing = program.getFunctionManager().getFunctionContaining(match);
                    if (containing != null && (!containing.getEntryPoint().equals(match)
                            || containing.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS))) {
                        log.appendMsg(NAME, "Preserving existing function/signature at " + match);
                        continue;
                    }
                    try {
                        AddressSet body = new AddressSet(match, end);
                        DisassembleCommand disassembly = new DisassembleCommand(match, body, true);
                        disassembly.enableCodeAnalysis(false);
                        if (!disassembly.applyTo(program, monitor) || !hasQualifiedInstructions(program, match)) {
                            log.appendMsg(NAME, "Complete bytes at " + match + " do not have the qualified native instruction boundaries");
                            continue;
                        }
                        Function function = containing;
                        if (function == null) {
                            function = program.getFunctionManager().createFunction("F_SCOPY", match, body, SourceType.ANALYSIS);
                        }
                        if (!installed) {
                            installConvention(program, monitor);
                            installed = true;
                        }
                        applyContract(program, function);
                        log.appendMsg(NAME, "Applied qualified F_SCOPY contract at " + match);
                    }
                    catch (CancelledException e) {
                        throw e;
                    }
                    catch (Exception e) {
                        log.appendMsg(NAME, "Failed to apply F_SCOPY at " + match + ": " + e.getMessage());
                        log.appendException(e);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean hasQualifiedInstructions(Program program, Address entry) {
        Address address = entry;
        for (int length : INSTRUCTION_LENGTHS) {
            Instruction instruction = program.getListing().getInstructionAt(address);
            if (instruction == null || instruction.getLength() != length) {
                return false;
            }
            address = address.add(length);
        }
        // Context can override a language's default operand/address size.
        for (String name : new String[] { "opsize", "addrsize" }) {
            var value = program.getProgramContext().getValue(program.getRegister(name), entry, false);
            if (value == null || value.signum() != 0) {
                return false;
            }
        }
        return true;
    }

    private void installConvention(Program program, TaskMonitor monitor) throws Exception {
        String xml;
        try (var input = Application.getModuleDataFile("borland-f-scopy.xml").getInputStream()) {
            xml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            throw new IOException("Missing native F_SCOPY prototype asset", e);
        }
        if (!xml.equals(SpecExtension.getCompilerSpecExtension(program, SpecExtension.Type.PROTOTYPE_MODEL, CONVENTION))) {
            new SpecExtension(program).addReplaceCompilerSpecExtension(xml, monitor);
        }
    }

    private void applyContract(Program program, Function function) throws Exception {
        var manager = program.getDataTypeManager();
        StructureDataType farAddress = new StructureDataType(new CategoryPath("/LegacyToolchains/Borland"), "FarAddress16", 0, manager);
        farAddress.add(UnsignedShortDataType.dataType, "offset", "16-bit offset");
        farAddress.add(UnsignedShortDataType.dataType, "selector", "16-bit selector/segment word; address mapping is not inferred");
        DataType addressType = manager.resolve(farAddress, DataTypeConflictHandler.DEFAULT_HANDLER);
        function.updateFunction(CONVENTION, new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, program.getRegister("CX"), program, SourceType.ANALYSIS),
            new ParameterImpl("source", addressType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("destination", addressType, 8, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(8);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("F_SCOPY", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland F_SCOPY]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
