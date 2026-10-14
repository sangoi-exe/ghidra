// Native integration check for the qualified SimTower NE helper and its real relocation-backed caller.
// Arguments: an existing task-private output directory.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import dev.sangoi.ghidra.legacy.BorlandFScopyAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class ValidateFScopy extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        require("New Executable (NE)".equals(currentProgram.getExecutableFormat()), "The primary case must use the native NE loader");
        Address helperAddress = mapped(0x5fc9);
        Function helper = currentProgram.getFunctionManager().getFunctionAt(helperAddress);
        require(helper != null && BorlandFScopyAnalyzer.CONVENTION.equals(helper.getCallingConventionName()), "The installed analyzer must have recognized the original helper during native analysis");

        int version = SpecExtension.getVersionCounter(currentProgram);
        MessageLog log = new MessageLog();
        BorlandFScopyAnalyzer analyzer = new BorlandFScopyAnalyzer();
        require(analyzer.added(currentProgram, new AddressSet(helperAddress, helperAddress.add(27)), monitor, log), "Production analyzer rerun failed: " + log);
        require(version == SpecExtension.getVersionCounter(currentProgram), "Unchanged prototype rerun must not reinstall the compiler specification");
        require(helper.hasCustomVariableStorage(), "Helper must retain explicit storage");
        require(helper.getStackPurgeSize() == 8, "RETF argument purge must be 8, not the full far-return delta");
        require(helper.getReturn().getVariableStorage().isVoidStorage(), "No AX/DX result is established");
        require(helper.getCallFixup() == null, "No copy-effect callfixup is part of this input/cleanup model");

        Parameter[] parameters = helper.getParameters();
        require(parameters.length == 3, "Implicit CX and two far-address records must be exposed");
        require(parameters[0].getLength() == 2 && parameters[0].getRegister().equals(currentProgram.getRegister("CX")), "Byte count must occupy 16-bit CX");
        for (int i = 1; i < 3; i++) {
            require(parameters[i].isStackVariable() && parameters[i].getStackOffset() == i * 4 && parameters[i].getLength() == 4, "Far-address storage must occupy entry stack +4/+8, four bytes each");
            require(parameters[i].getDataType() instanceof Structure, "Far address is a mechanical offset/selector record, not an inferred flat pointer");
            Structure record = (Structure) parameters[i].getDataType();
            require(record.getNumComponents() == 2 && record.getComponent(0).getOffset() == 0 && record.getComponent(1).getOffset() == 2, "Far-address record must preserve offset then selector words");
        }
        PrototypeModel prototype = helper.getCallingConvention();
        require(prototype.getStackshift() == 4 && prototype.getExtrapop() == 12, "Far return requires stackshift 4 and total extrapop 12");
        for (String name : new String[] { "AX", "BX", "DX", "BP", "SI", "DI", "DS", "SS" }) {
            require(containsRegister(prototype.getUnaffectedList(), name), "Missing established preservation: " + name);
        }
        for (String name : new String[] { "ES", "CX", "DF" }) {
            require(!containsRegister(prototype.getUnaffectedList(), name), "Unsupported preservation: " + name);
            require(containsRegister(prototype.getKilledByCallList(), name), "Missing post-call clobber boundary: " + name);
        }

        StringBuilder contract = new StringBuilder();
        contract.append("Ghidra ").append(getGhidraVersion()).append("\nFormat ").append(currentProgram.getExecutableFormat()).append("\nLanguage ").append(currentProgram.getLanguageID()).append('\n');
        contract.append("Original helper file [5fc9,5fe5) maps to ").append(helperAddress).append("\nFunction ").append(helper.getPrototypeString(true, true)).append('\n');
        for (Parameter parameter : parameters) {
            contract.append("PARAM ").append(parameter.getOrdinal()).append(' ').append(parameter.getName()).append(' ').append(parameter.getDataType().getPathName()).append(' ').append(parameter.getVariableStorage()).append('\n');
        }
        contract.append("purge=").append(helper.getStackPurgeSize()).append(" stackshift=").append(prototype.getStackshift()).append(" extrapop=").append(prototype.getExtrapop()).append("\nunaffected=").append(Arrays.toString(prototype.getUnaffectedList())).append("\nkilledbycall=").append(Arrays.toString(prototype.getKilledByCallList())).append('\n');
        contract.append("Idempotent production rerun: compiler-spec version ").append(version).append(" unchanged\n").append(log).append('\n');
        contract.append(helper.getComment()).append('\n');
        Files.writeString(output.resolve("contract.txt"), contract);
        exportInstructions(output.resolve("helper-instructions-pcode.txt"), new AddressSet(helperAddress, helperAddress.add(27)));

        Address callerAddress = mapped(0x33e87);
        AddressSet callerBody = new AddressSet(callerAddress, mapped(0x340f9));
        DisassembleCommand disassembly = new DisassembleCommand(callerAddress, callerBody, true);
        disassembly.enableCodeAnalysis(false);
        require(disassembly.applyTo(currentProgram, monitor), "Native original-caller disassembly failed: " + disassembly.getStatusMsg());
        Function caller = currentProgram.getFunctionManager().getFunctionContaining(callerAddress);
        if (caller == null) {
            caller = currentProgram.getFunctionManager().createFunction("qualified_f_scopy_caller", callerAddress, callerBody, SourceType.ANALYSIS);
        }
        StringBuilder calls = new StringBuilder();
        for (long fileOffset : new long[] { 0x33eab, 0x33ec9, 0x33fb8 }) {
            Address call = mapped(fileOffset);
            var instruction = currentProgram.getListing().getInstructionAt(call);
            require(instruction != null && instruction.getFlowType().isCall(), "Original relocation-backed call must remain a native call at " + call);
            require(Arrays.asList(instruction.getFlows()).contains(helperAddress), "Original far call must resolve to the recognized helper at " + call);
            calls.append("CALL file=").append(Long.toHexString(fileOffset)).append(" native=").append(call).append(' ').append(instruction).append(" target=").append(helperAddress).append('\n');
        }
        Files.writeString(output.resolve("caller-calls.txt"), calls);
        exportInstructions(output.resolve("caller-instructions-pcode.txt"), callerBody);

        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler failed to open the Program: " + decompiler.getLastMessage());
            DecompileResults helperResult = decompile(decompiler, helper, output.resolve("helper.c"));
            require(helperResult.getHighFunction().getFunctionPrototype().getExtraPop() == 12, "Native decompiler must consume the far-return extrapop, not 8");
            DecompileResults callerResult = decompile(decompiler, caller, output.resolve("caller.c"));
            StringBuilder highCalls = new StringBuilder();
            int matched = 0;
            var operations = callerResult.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                PcodeOp operation = operations.next();
                if (operation.getOpcode() == PcodeOp.CALL && operation.getInput(0).getAddress().equals(helperAddress)) {
                    require(operation.getNumInputs() == 4 && operation.getInput(1).getSize() == 2 && operation.getInput(2).getSize() == 4 && operation.getInput(3).getSize() == 4, "Actual caller HighFunction must carry CX and two complete address pairs");
                    require(operation.getInput(1).isConstant() && (operation.getInput(1).getOffset() == 8 || operation.getInput(1).getOffset() == 16), "Actual caller must propagate the evidenced CX byte counts");
                    highCalls.append(operation.getSeqnum().getTarget()).append(' ').append(operation).append('\n');
                    matched++;
                }
            }
            require(matched == 3, "Expected the three original helper calls in the actual caller HighFunction, got " + matched);
            Files.writeString(output.resolve("caller-high-calls.txt"), highCalls);
        }
        finally {
            decompiler.dispose();
        }
        println("F_SCOPY VALIDATION PASS: native NE recognition; CX/offset-selector storage; far cleanup; no false ES/DF preservation; three real caller inputs. Outputs: " + output);
    }

    private Address mapped(long fileOffset) {
        List<Address> mappings = currentProgram.getMemory().locateAddressesForFileOffset(fileOffset);
        require(mappings.size() == 1, "Expected one native original file mapping for " + Long.toHexString(fileOffset) + ": " + mappings);
        return mappings.get(0);
    }

    private boolean containsRegister(Varnode[] nodes, String name) {
        var register = currentProgram.getRegister(name);
        return Arrays.stream(nodes).anyMatch(node -> node.getAddress().equals(register.getAddress()) && node.getSize() == register.getMinimumByteSize());
    }

    private void exportInstructions(Path output, AddressSet body) throws Exception {
        StringBuilder listing = new StringBuilder();
        for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
            listing.append(instruction.getAddress()).append(' ').append(HexFormat.of().formatHex(instruction.getBytes())).append(' ').append(instruction).append('\n');
            for (PcodeOp operation : instruction.getPcode()) {
                listing.append("  PCODE ").append(operation).append('\n');
            }
        }
        Files.writeString(output, listing);
    }

    private DecompileResults decompile(DecompInterface decompiler, Function function, Path output) throws Exception {
        DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
        require(result.decompileCompleted() && result.getHighFunction() != null, "Native decompilation failed at " + function.getEntryPoint() + ": " + result.getErrorMessage());
        Files.writeString(output, "/* Native evidence only; not proof of faithful historical C. " + result.getErrorMessage() + " */\n" + result.getDecompiledFunction().getC());
        return result;
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
