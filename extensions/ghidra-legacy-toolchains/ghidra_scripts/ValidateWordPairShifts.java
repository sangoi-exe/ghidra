// Native static integration check on the supplied original SCRANTIC.EXE, not legacy execution.
// Arguments: an existing task-private output directory.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;

import dev.sangoi.ghidra.legacy.BorlandWordPairShiftAnalyzer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class ValidateWordPairShifts extends GhidraScript {
    private static final long[] NEAR_FILE = { 0xc85, 0xca6, 0xcc6 };
    private static final String[] NAMES = { "left", "arithmetic_right", "logical_right" };
    private static final String[] BYTES = {
        "5b0e5380f91073108bd8d3e0d3e2f6d980c110d3eb0bd3cb80e9109233c0d3e2cb",
        "5b0e5380f91073108bdad3e8d3faf6d980c110d3e30bc3cb80e9109299d3f8cb",
        "5b0e5380f91073108bdad3e8d3eaf6d980c110d3e30bc3cb80e9109233d2d3e8cb"
    };

    @Override
    protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        require("New Executable (NE)".equals(currentProgram.getExecutableFormat()), "Primary evidence requires the native NE loader");
        StringBuilder report = new StringBuilder("Ghidra " + getGhidraVersion() + "\nStatic original-byte/native-analysis evidence; no original or reconstructed legacy execution.\n");
        LinkedHashSet<Function> callers = new LinkedHashSet<>();
        Function[] cores = new Function[3];
        BasicBlockModel blocks = new BasicBlockModel(currentProgram);
        for (int member = 0; member < 3; member++) {
            Address near = mapped(NEAR_FILE[member]);
            Address core = near.add(3);
            Address end = near.add(BYTES[member].length() / 2 - 1);
            byte[] bytes = new byte[BYTES[member].length() / 2];
            require(currentProgram.getMemory().getBytes(near, bytes) == bytes.length && HexFormat.of().formatHex(bytes).equals(BYTES[member]), "Complete original member bytes must agree");
            Function function = currentProgram.getFunctionManager().getFunctionAt(core);
            cores[member] = function;
            require(function != null && function.getBody().equals(new AddressSet(core, end)), "Native owner must be the exact complete far core, not the adapter or adjacent body");
            require(BorlandWordPairShiftAnalyzer.CONVENTION.equals(function.getCallingConventionName()), "Installed production analyzer must recognize all three cores");
            require(currentProgram.getFunctionManager().getFunctionContaining(near) == null, "Adapter must not become a fake three-byte returning function");
            require(currentProgram.getSymbolTable().getSymbol("qualified_word_shift_" + NAMES[member] + "_near_adapter", near, null) != null && currentProgram.getSymbolTable().getSymbol("qualified_word_shift_" + NAMES[member] + "_far_core", core, null) != null, "Both proved entrypoints must be labeled");
            String nearComment = currentProgram.getListing().getComment(CommentType.PLATE, near);
            require(nearComment.contains("2-byte") && nearComment.contains("4-byte") && nearComment.contains(core.toString()), "Near-to-far frame relationship must be explicit");
            for (int i = 0; i < 3; i++) {
                var instruction = currentProgram.getListing().getInstructionAt(near.add(i));
                require(instruction != null && instruction.getLength() == 1 && instruction.getFallThrough().equals(near.add(i + 1)), "All adapter instructions must retain real native fallthrough into the core");
            }
            require(!currentProgram.getReferenceManager().getReferencesTo(near).hasNext(), "No near caller was observed in the original native import");
            int instructionCount = 0;
            int returns = 0;
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                instructionCount++;
                if (instruction.getFlowType().isTerminal()) {
                    require(HexFormat.of().formatHex(instruction.getBytes()).equals("cb"), "Core exits must be plain RETF");
                    returns++;
                }
            }
            var blockIterator = blocks.getCodeBlocksContaining(function.getBody(), monitor);
            int blockCount = 0;
            while (blockIterator.hasNext()) {
                var block = blockIterator.next();
                require(function.getBody().contains(block), "Core blocks must not include adapter/separator bytes");
                blockCount++;
            }
            require(instructionCount == 15 && returns == 2 && blockCount == 3, "Each complete core must have 15 instructions, three blocks and two RETF exits");
            require(function.hasCustomVariableStorage() && function.getStackPurgeSize() == 0 && function.getCallFixup() == null, "Far core must have no argument purge or replacement semantics");
            var parameters = function.getParameters();
            require(parameters.length == 2 && parameters[0].getName().equals("value") && parameters[0].getLength() == 4 && pair(parameters[0].getVariableStorage().getVarnodes()) && parameters[1].getName().equals("count") && parameters[1].getLength() == 1 && isRegister(parameters[1].getVariableStorage().getVarnodes()[0], "CL"), "Only DX:AX and unsigned CL are inputs");
            require(pair(function.getReturn().getVariableStorage().getVarnodes()) && function.getReturnType().getLength() == 4, "Result must be the complete DX:AX pair");
            var prototype = function.getCallingConvention();
            require(prototype.getStackshift() == 4 && prototype.getExtrapop() == 4, "Far core must consume exactly its four-byte return frame");
            for (String name : new String[] { "CH", "BP", "SI", "DI", "DS", "ES" }) {
                require(contains(prototype.getUnaffectedList(), name), "Missing qualified preservation " + name);
            }
            for (String name : new String[] { "AX", "DX", "BX", "CL", "CF", "PF", "AF", "ZF", "SF", "OF" }) {
                require(!contains(prototype.getUnaffectedList(), name) && contains(prototype.getKilledByCallList(), name), "Missing scratch/flag boundary " + name);
            }
            require(function.getComment().contains("0..31") && function.getComment().contains("final CL=16-n") && function.getComment().contains("final CL=n-16") && function.getComment().contains("no clamp"), "Qualified count/result domain and CL effects must remain explicit");
            int calls = 0;
            for (var reference : currentProgram.getReferenceManager().getReferencesTo(core)) {
                var instruction = currentProgram.getListing().getInstructionAt(reference.getFromAddress());
                if (instruction == null || !instruction.getFlowType().isCall()) {
                    continue;
                }
                require(instruction.getMnemonicString().equals("CALLF") && Arrays.asList(instruction.getFlows()).contains(core), "Actual original caller must be a resolved native far call");
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
                require(caller != null, "Observed far call must have an actual native function owner");
                callers.add(caller);
                calls++;
                report.append(NAMES[member]).append(" actual native far call ").append(instruction.getAddress()).append(' ').append(instruction).append(" owner ").append(caller.getEntryPoint()).append('\n');
            }
            require(calls == (member == 0 ? 5 : 1), "Native observed far-call frontier changed; do not equate raw candidates with executable callers");
            report.append(NAMES[member]).append(" adapter=").append(near).append(" core=").append(core).append(" body=").append(function.getBody()).append("\n").append(function.getPrototypeString(true, true)).append(" input=").append(parameters[0].getVariableStorage()).append(',').append(parameters[1].getVariableStorage()).append(" return=").append(function.getReturn().getVariableStorage()).append("\n").append(function.getComment()).append('\n');
            exportInstructions(output.resolve(NAMES[member] + "-instructions-pcode.txt"), new AddressSet(near, end));
        }
        require(currentProgram.getMemory().getByte(mapped(0xce7)) == 0 && currentProgram.getListing().getInstructionContaining(mapped(0xce7)) == null && currentProgram.getFunctionManager().getFunctionContaining(mapped(0xce7)) == null, "Final 00 separator must not be code or function-owned");
        AddressSet family = new AddressSet(mapped(0xc85), mapped(0xce6));
        int version = SpecExtension.getVersionCounter(currentProgram);
        String[] comments = Arrays.stream(cores).map(Function::getComment).toArray(String[]::new);
        MessageLog log = new MessageLog();
        require(new BorlandWordPairShiftAnalyzer().added(currentProgram, family, monitor, log), "Production repeat failed: " + log);
        require(SpecExtension.getVersionCounter(currentProgram) == version, "Unchanged convention must not reinstall");
        for (int i = 0; i < 3; i++) {
            require(comments[i].equals(cores[i].getComment()), "Repeat must not duplicate comments");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler must open Program");
            for (Function function : cores) {
                var result = decompiler.decompileFunction(function, 60, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Core decompilation failed: " + result.getErrorMessage());
                require(result.getHighFunction().getFunctionPrototype().getExtraPop() == 4, "Core HighFunction must retain far return pop");
                Files.writeString(output.resolve(function.getName() + ".c"), "/* Native analysis output; not historical C or universal host shift semantics. */\n" + result.getDecompiledFunction().getC());
                exportHigh(output.resolve(function.getName() + "-high.txt"), result.getHighFunction().getPcodeOps());
            }
            StringBuilder highCalls = new StringBuilder();
            int matched = 0;
            for (Function caller : callers) {
                var result = decompiler.decompileFunction(caller, 90, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Actual caller decompilation failed: " + result.getErrorMessage());
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    var operation = operations.next();
                    if (operation.getOpcode() != PcodeOp.CALL) {
                        continue;
                    }
                    for (Function core : cores) {
                        if (operation.getInput(0).getAddress().equals(core.getEntryPoint())) {
                            require(operation.getNumInputs() == 3 && operation.getInput(1).getSize() == 4 && operation.getInput(2).getSize() == 1 && operation.getOutput() != null && operation.getOutput().getSize() == 4, "Actual caller HighFunction must expose pair/count inputs and full returned pair");
                            highCalls.append(operation.getSeqnum().getTarget()).append(' ').append(operation).append('\n');
                            matched++;
                        }
                    }
                }
                Files.writeString(output.resolve("caller-" + caller.getEntryPoint().toString().replace(':', '-') + ".c"), "/* Native analysis output; other caller effects remain unresolved. */\n" + result.getDecompiledFunction().getC());
                exportInstructions(output.resolve("caller-" + caller.getEntryPoint().toString().replace(':', '-') + "-instructions-pcode.txt"), new AddressSet(caller.getBody()));
            }
            require(matched == 7, "All seven observed native far calls must remain in actual caller HighFunctions");
            Files.writeString(output.resolve("caller-high-calls.txt"), highCalls);
        }
        finally {
            decompiler.dispose();
        }
        // Protect a real user signature on the original native function, not a synthetic external ABI.
        cores[0].setName("user_word_shift", SourceType.USER_DEFINED);
        cores[0].setSignatureSource(SourceType.USER_DEFINED);
        cores[0].setStackPurgeSize(6);
        cores[0].setComment("User-owned signature and comment");
        require(new BorlandWordPairShiftAnalyzer().added(currentProgram, family, monitor, log), "User-retention repeat failed: " + log);
        require(cores[0].getSignatureSource() == SourceType.USER_DEFINED && cores[0].getName().equals("user_word_shift") && cores[0].getStackPurgeSize() == 6 && cores[0].getComment().equals("User-owned signature and comment"), "Higher-priority user contract must survive recognition");
        report.append("Repeat stable; higher-priority user signature/name/purge/comment retained. No near caller observed. Native raw/p-code and C/High exports are static evidence, not original execution or a proof of out-of-range shifts.\n").append(log);
        Files.writeString(output.resolve("contract.txt"), report);
        println("WORD PAIR SHIFTS VALIDATION PASS: complete 98 executable bytes, 00 separator excluded; three real adapters and non-overlapping 15-instruction/three-block/two-RETF cores; DX:AX/CL, far4/purge0, seven original far calls with actual HighFunction inputs/results; repeat and user-contract retention.");
    }

    private boolean pair(Varnode[] nodes) {
        return nodes.length == 2 && isRegister(nodes[0], "DX") && isRegister(nodes[1], "AX");
    }

    private boolean isRegister(Varnode node, String name) {
        var register = currentProgram.getRegister(name);
        return node.getAddress().equals(register.getAddress()) && node.getSize() == register.getMinimumByteSize();
    }

    private boolean contains(Varnode[] nodes, String name) {
        return Arrays.stream(nodes).anyMatch(node -> isRegister(node, name));
    }

    private Address mapped(long fileOffset) {
        var addresses = currentProgram.getMemory().locateAddressesForFileOffset(fileOffset);
        require(addresses.size() == 1, "Expected unique original file mapping: " + Long.toHexString(fileOffset) + " " + addresses);
        return addresses.get(0);
    }

    private void exportInstructions(Path output, AddressSet body) throws Exception {
        StringBuilder report = new StringBuilder();
        for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
            report.append(instruction.getAddress()).append(' ').append(HexFormat.of().formatHex(instruction.getBytes())).append(' ').append(instruction).append('\n');
            for (var operation : instruction.getPcode()) {
                report.append("  PCODE ").append(operation).append('\n');
            }
        }
        Files.writeString(output, report);
    }

    private void exportHigh(Path output, java.util.Iterator<ghidra.program.model.pcode.PcodeOpAST> operations) throws Exception {
        StringBuilder report = new StringBuilder();
        while (operations.hasNext()) {
            report.append(operations.next()).append('\n');
        }
        Files.writeString(output, report);
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
