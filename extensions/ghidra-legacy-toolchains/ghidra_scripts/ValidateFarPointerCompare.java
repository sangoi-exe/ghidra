// Native original-input check; argument: an existing task-private output directory.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import dev.sangoi.ghidra.legacy.BorlandFarPointerCompareAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class ValidateFarPointerCompare extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        require("New Executable (NE)".equals(currentProgram.getExecutableFormat()), "Requires original native NE input");
        Address entry = mapped(0xb19);
        Function helper = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(helper != null && BorlandFarPointerCompareAnalyzer.CONVENTION.equals(helper.getCallingConventionName()), "Installed analyzer must recognize complete original helper automatically");
        checkBytes(0xb19, "518ae8b104d3e803d08ac58ae3d3eb5903cb8adc250f0083e30f3bd175023bc3cb");
        require(helper.getBody().equals(new AddressSet(entry, entry.add(32))), "Exact 33-byte native body");
        int instructions = 0;
        for (var instruction : currentProgram.getListing().getInstructions(helper.getBody(), true)) {
            instructions++;
        }
        require(instructions == 17, "Exact 17 native instructions");
        require(helper.hasCustomVariableStorage() && helper.getCallFixup() == null && helper.getStackPurgeSize() == 0, "Native storage without fixup or argument purge");
        var parameters = helper.getParameters();
        require(parameters.length == 2 && parameters[0].getLength() == 4 && parameters[1].getLength() == 4, "Two input word-pair records");
        checkStorage(parameters[0].getVariableStorage().getVarnodes(), "DX", "AX");
        checkStorage(parameters[1].getVariableStorage().getVarnodes(), "CX", "BX");
        require(helper.getReturnType() instanceof Structure, "Analysis result is not AX boolean");
        Structure state = (Structure) helper.getReturnType();
        require(state.getLength() == 9 && state.getNumComponents() == 5 && state.getComponent(0).getFieldName().equals("equal_zf"), "Nine-byte ZF and four-word native result");
        for (int i = 0; i < 5; i++) {
            require(state.getComponent(i).getOffset() == (i == 0 ? 0 : 2 * i - 1), "Packed physical result field " + i);
        }
        checkStorage(helper.getReturn().getVariableStorage().getVarnodes(), "CX", "BX", "DX", "AX", "ZF");
        var convention = helper.getCallingConvention();
        require(convention.getExtrapop() == 4 && convention.getStackshift() == 4, "Plain far return pop4/shift4");
        for (String name : new String[] { "BP", "SI", "DI", "DS", "ES", "SS", "DF" }) {
            require(containsRegister(convention.getUnaffectedList(), name), "Missing untouched register " + name);
        }
        for (String name : new String[] { "AX", "DX", "BX", "CX", "CF", "PF", "AF", "ZF", "SF", "OF" }) {
            require(!containsRegister(convention.getUnaffectedList(), name) && containsRegister(convention.getKilledByCallList(), name), "Unsupported preservation " + name);
        }
        int version = SpecExtension.getVersionCounter(currentProgram);
        String before = helper.getPrototypeString(true, true) + helper.getComment();
        MessageLog log = new MessageLog();
        require(new BorlandFarPointerCompareAnalyzer().added(currentProgram, helper.getBody(), monitor, log), "Analyzer rerun");
        require(version == SpecExtension.getVersionCounter(currentProgram) && before.equals(helper.getPrototypeString(true, true) + helper.getComment()), "Unchanged recognition must be stable");
        Files.writeString(output.resolve("contract.txt"), helper.getPrototypeString(true, true) + "\nreturn=" + helper.getReturn().getVariableStorage() + "\ninputs=" + Arrays.toString(parameters) + "\nunaffected=" + Arrays.toString(convention.getUnaffectedList()) + "\nkilled=" + Arrays.toString(convention.getKilledByCallList()) + "\n" + helper.getComment() + "\n" + log);
        exportInstructions(output.resolve("helper-raw-pcode.txt"), new AddressSet(helper.getBody()));

        // The complete recovered caller owns this branch, not a synthetic boolean-call fixture.
        Address callerEntry = mapped(0xdd63);
        AddressSet callerBody = new AddressSet(callerEntry, mapped(0xddb3));
        DisassembleCommand command = new DisassembleCommand(callerEntry, callerBody, true);
        command.enableCodeAnalysis(false);
        require(command.applyTo(currentProgram, monitor), "Original complete NE7:1b63 caller disassembly");
        Function caller = currentProgram.getFunctionManager().getFunctionAt(callerEntry);
        if (caller == null) {
            caller = currentProgram.getFunctionManager().createFunction("qualified_far_pointer_compare_caller", callerEntry, callerBody, SourceType.ANALYSIS);
        }
        checkBytes(0xdd6d, "33c933db8b56088b4606");
        checkBytes(0xdd7c, "7432");
        var call = currentProgram.getListing().getInstructionAt(mapped(0xdd77));
        require(call != null && call.getFlowType().isCall() && Arrays.asList(call.getFlows()).contains(entry), "Original native relocation-backed CALL resolves to comparator");
        var branch = currentProgram.getListing().getInstructionAt(mapped(0xdd7c));
        require(Arrays.asList(branch.getFlows()).contains(mapped(0xddb0)) && branch.getFallThrough().equals(mapped(0xdd7e)), "Actual immediate JE target/fallthrough");
        exportInstructions(output.resolve("caller-raw-pcode.txt"), callerBody);

        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler open");
            for (Function function : new Function[] { helper, caller }) {
                var result = decompiler.decompileFunction(function, 60, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Native decompilation: " + result.getErrorMessage());
                String name = function == helper ? "helper" : "caller";
                Files.writeString(output.resolve(name + ".c"), "/* Native analysis output, not historical C. */\n" + result.getDecompiledFunction().getC());
                StringBuilder high = new StringBuilder();
                PcodeOp highCall = null;
                PcodeOp highBranch = null;
                boolean firstShift = false;
                boolean secondShift = false;
                boolean firstSum = false;
                boolean secondSum = false;
                boolean firstMask = false;
                boolean secondMask = false;
                boolean normalizedEquality = false;
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    var operation = operations.next();
                    high.append(operation.getSeqnum()).append(' ').append(operation).append('\n');
                    if (function == helper) {
                        Address at = operation.getSeqnum().getTarget();
                        if (operation.getOpcode() == PcodeOp.INT_RIGHT && operation.getOutput().getSize() == 2 && operation.getInput(1).isConstant() && operation.getInput(1).getOffset() == 4) {
                            firstShift |= at.equals(mapped(0xb1e));
                            secondShift |= at.equals(mapped(0xb26));
                        }
                        if (operation.getOpcode() == PcodeOp.INT_ADD) {
                            firstSum |= at.equals(mapped(0xb20)) && isRegister(operation.getOutput(), "DX");
                            secondSum |= at.equals(mapped(0xb29)) && isRegister(operation.getOutput(), "CX");
                        }
                        if (operation.getOpcode() == PcodeOp.INT_AND && operation.getOutput().getSize() == 2 && operation.getInput(1).isConstant() && operation.getInput(1).getOffset() == 15) {
                            firstMask |= at.equals(mapped(0xb2d));
                            secondMask |= at.equals(mapped(0xb30));
                        }
                        if (operation.getOpcode() == PcodeOp.BOOL_AND) {
                            normalizedEquality |= isComparison(operation.getInput(0), "DX", "CX") && isComparison(operation.getInput(1), "AX", "BX");
                        }
                    }
                    if (operation.getOpcode() == PcodeOp.CALL && operation.getSeqnum().getTarget().equals(mapped(0xdd77))) {
                        highCall = operation;
                    }
                    if (operation.getOpcode() == PcodeOp.CBRANCH && operation.getSeqnum().getTarget().equals(mapped(0xdd7c))) {
                        highBranch = operation;
                    }
                }
                Files.writeString(output.resolve(name + "-high.txt"), high);
                if (function == helper) {
                    require(result.getHighFunction().getFunctionPrototype().getExtraPop() == 4, "Native helper return consumes four return bytes");
                    require(firstShift && secondShift && firstSum && secondSum && firstMask && secondMask && normalizedEquality, "Native helper HighFunction must retain finite WORD shifts/sums/nibbles and the conjunction of high/low equalities");
                }
                else {
                    require(highCall != null && highCall.getInput(0).getAddress().equals(entry) && highCall.getNumInputs() == 3 && highCall.getInput(1).getSize() == 4 && highCall.getInput(2).getSize() == 4, "Actual caller carries two native input pairs");
                    require(highCall.getOutput() != null && highCall.getOutput().getSize() == 9, "Actual call retains joined nine-byte result");
                    require(highBranch != null && dependsOnFlag(highBranch.getInput(1), highCall.getOutput(), new HashSet<>()), "Actual immediate CBRANCH must depend on returned ZF byte, not unrelated or invented bool storage");
                    Files.writeString(output.resolve("caller-zf-dependency.txt"), highCall + "\n" + highBranch + "\nActual NE7:1b77 CALL joined result -> offset-zero ZF extraction -> NE7:1b7c CBRANCH. Taken1bb0/fallthrough1b7e. No claim for other callers.\n");
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        // USER_DEFINED signature is outside the production analyzer's authority.
        helper.setSignatureSource(SourceType.USER_DEFINED);
        helper.setComment("User-owned comparator contract");
        String userContract = helper.getPrototypeString(true, true);
        require(new BorlandFarPointerCompareAnalyzer().added(currentProgram, helper.getBody(), monitor, log), "User-owned rerun");
        require(helper.getSignatureSource() == SourceType.USER_DEFINED && helper.getComment().equals("User-owned comparator contract") && helper.getPrototypeString(true, true).equals(userContract), "User-owned contract must remain unchanged");
        println("FAR POINTER COMPARE VALIDATION PASS: automatic original33/17; normalized word/ZF tuple9; far shift4/pop4/purge0; native actual CALL-to-CBRANCH ZF dependency; repeat stability; user signature preserved.");
    }

    private boolean isComparison(Varnode value, String left, String right) {
        var definition = value.getDef();
        return definition != null && definition.getOpcode() == PcodeOp.INT_EQUAL && isRegister(definition.getInput(0), left) && isRegister(definition.getInput(1), right);
    }

    private boolean dependsOnFlag(Varnode value, Varnode result, Set<Varnode> visited) {
        if (!visited.add(value) || value.getDef() == null) {
            return false;
        }
        var definition = value.getDef();
        if (definition.getOpcode() == PcodeOp.SUBPIECE && definition.getInput(0).equals(result) && definition.getInput(1).isConstant() && definition.getInput(1).getOffset() == 0 && value.getSize() == 1) {
            return true;
        }
        for (int i = 0; i < definition.getNumInputs(); i++) {
            if (dependsOnFlag(definition.getInput(i), result, visited)) {
                return true;
            }
        }
        return false;
    }

    private Address mapped(long offset) {
        List<Address> mappings = currentProgram.getMemory().locateAddressesForFileOffset(offset);
        require(mappings.size() == 1, "One native file mapping for " + Long.toHexString(offset));
        return mappings.get(0);
    }

    private boolean isRegister(Varnode node, String name) {
        var register = currentProgram.getRegister(name);
        return node.getAddress().equals(register.getAddress()) && node.getSize() == register.getMinimumByteSize();
    }

    private boolean containsRegister(Varnode[] nodes, String name) {
        return Arrays.stream(nodes).anyMatch(node -> isRegister(node, name));
    }

    private void checkStorage(Varnode[] nodes, String... names) {
        require(nodes.length == names.length, "Native storage piece count");
        for (int i = 0; i < names.length; i++) {
            require(isRegister(nodes[i], names[i]), "Native storage order " + names[i]);
        }
    }

    private void checkBytes(long offset, String expected) throws Exception {
        byte[] bytes = new byte[expected.length() / 2];
        require(currentProgram.getMemory().getBytes(mapped(offset), bytes) == bytes.length && HexFormat.of().formatHex(bytes).equals(expected), "Original bytes at file " + Long.toHexString(offset));
    }

    private void exportInstructions(Path output, AddressSet body) throws Exception {
        StringBuilder listing = new StringBuilder();
        for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
            listing.append(instruction.getAddress()).append(' ').append(HexFormat.of().formatHex(instruction.getBytes())).append(' ').append(instruction).append('\n');
            for (var operation : instruction.getPcode()) {
                listing.append("  ").append(operation).append('\n');
            }
        }
        Files.writeString(output, listing);
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
