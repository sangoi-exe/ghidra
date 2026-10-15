// Native original-input check; arguments: an existing task-private output directory.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import dev.sangoi.ghidra.legacy.BorlandFarCopyAnalyzer;
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

public class ValidateFarCopy extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        require("New Executable (NE)".equals(currentProgram.getExecutableFormat()), "Primary evidence requires the native NE loader");
        Address entry = mapped(0x3422);
        Function helper = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(helper != null && BorlandFarCopyAnalyzer.CONVENTION.equals(helper.getCallingConventionName()), "Installed production analyzer must recognize the original body during analysis");
        byte[] bytes = new byte[38];
        require(currentProgram.getMemory().getBytes(entry, bytes) == 38 && HexFormat.of().formatHex(bytes).equals("45558bec56578cdac47e06c5760a8b4e0ed1e9fcf3a57301a48eda8b56088b46065f5e5d4dcb"), "Complete original helper bytes must agree");
        require(helper.getBody().getNumAddresses() == 38, "Qualified body must contain exactly 38 bytes");
        int instructions = 0;
        for (var instruction : currentProgram.getListing().getInstructions(new AddressSet(entry, entry.add(37)), true)) {
            instructions++;
        }
        require(instructions == 22, "Qualified native body must contain 22 instructions");
        int version = SpecExtension.getVersionCounter(currentProgram);
        MessageLog log = new MessageLog();
        require(new BorlandFarCopyAnalyzer().added(currentProgram, new AddressSet(entry, entry.add(37)), monitor, log), "Production rerun failed: " + log);
        require(SpecExtension.getVersionCounter(currentProgram) == version, "Unchanged native prototype must not reinstall");
        require(helper.hasCustomVariableStorage() && helper.getStackPurgeSize() == 0 && helper.getCallFixup() == null, "Plain RETF must retain caller arguments and no invented copy-effect fixup");
        var parameters = helper.getParameters();
        require(parameters.length == 3, "Destination/source/count are the only inputs; no incoming GPR argument");
        String[] names = { "destination", "source", "byte_count" };
        for (int i = 0; i < 3; i++) {
            require(parameters[i].getName().equals(names[i]) && parameters[i].isStackVariable() && parameters[i].getStackOffset() == 4 + 4 * i && parameters[i].getLength() == (i == 2 ? 2 : 4), "Wrong entry-stack input " + names[i]);
            if (i < 2) {
                requireFarRecord(parameters[i].getDataType());
            }
        }
        requireFarRecord(helper.getReturnType());
        Varnode[] returned = helper.getReturn().getVariableStorage().getVarnodes();
        require(returned.length == 2 && isRegister(returned[0], "DX") && isRegister(returned[1], "AX"), "Result must be selector DX then offset AX, not a host pointer");
        var prototype = helper.getCallingConvention();
        require(prototype.getStackshift() == 4 && prototype.getExtrapop() == 4, "Far return shift/pop must be 4, not argument cleanup");
        for (String name : new String[] { "BX", "BP", "SI", "DI", "DS", "SS" }) {
            require(containsRegister(prototype.getUnaffectedList(), name), "Missing qualified low16 preservation " + name);
        }
        for (String name : new String[] { "AX", "DX", "CX", "ES", "DF", "CF", "PF", "AF", "ZF", "SF", "OF" }) {
            require(!containsRegister(prototype.getUnaffectedList(), name) && containsRegister(prototype.getKilledByCallList(), name), "Unsupported preservation or missing clobber " + name);
        }
        StringBuilder contract = new StringBuilder("Ghidra " + getGhidraVersion() + "\n" + helper.getPrototypeString(true, true) + "\n");
        for (var parameter : parameters) {
            contract.append(parameter.getName()).append(' ').append(parameter.getDataType().getPathName()).append(' ').append(parameter.getVariableStorage()).append('\n');
        }
        contract.append("return=").append(helper.getReturn().getVariableStorage()).append(" purge=").append(helper.getStackPurgeSize()).append(" stackshift=").append(prototype.getStackshift()).append(" extrapop=").append(prototype.getExtrapop()).append("\nunaffected=").append(Arrays.toString(prototype.getUnaffectedList())).append("\nkilledbycall=").append(Arrays.toString(prototype.getKilledByCallList())).append('\n').append(helper.getComment()).append('\n').append(log);
        Files.writeString(output.resolve("contract.txt"), contract);
        exportInstructions(output.resolve("helper-instructions-pcode.txt"), new AddressSet(entry, entry.add(37)));

        Address callerEntry = mapped(0x3e0ea);
        AddressSet callerBody = new AddressSet(callerEntry, mapped(0x3e23c));
        DisassembleCommand disassembly = new DisassembleCommand(callerEntry, callerBody, true);
        disassembly.enableCodeAnalysis(false);
        require(disassembly.applyTo(currentProgram, monitor), "Complete original controller disassembly failed");
        Function caller = currentProgram.getFunctionManager().getFunctionAt(callerEntry);
        if (caller == null) {
            caller = currentProgram.getFunctionManager().createFunction("qualified_far_copy_caller", callerEntry, callerBody, SourceType.ANALYSIS);
        }
        for (long offset : new long[] { 0x3e14a, 0x3e1e6 }) {
            var call = currentProgram.getListing().getInstructionAt(mapped(offset));
            require(call != null && call.getFlowType().isCall() && Arrays.asList(call.getFlows()).contains(entry), "Original relocation-backed call must resolve to helper at file " + Long.toHexString(offset));
            byte[] cleanup = new byte[3];
            currentProgram.getMemory().getBytes(mapped(offset + 5), cleanup);
            require(HexFormat.of().formatHex(cleanup).equals("83c40a"), "Original caller must remove ten argument bytes after far return");
        }
        byte[] frame = new byte[15];
        currentProgram.getMemory().getBytes(mapped(0x3e13b), frame);
        require(HexFormat.of().formatHex(frame).equals("ff76f8168d86f3fe50168d86f2fe50"), "Aligned first caller must push current BP-8 count, SS:BP-10d source, SS:BP-10e destination");
        exportInstructions(output.resolve("caller-instructions-pcode.txt"), callerBody);
        Files.writeString(output.resolve("caller-qualification.txt"), "NE51 complete [02ea,043d), file [3e0ea,3e23d). Calls 034a/03e6 resolve to NE1:1222; both ADD SP,0a retain caller-owned ten bytes. First frame [033b,034a): PUSH current WORD [BP-8], PUSH SS, LEA AX,[BP-10d], PUSH AX, PUSH SS, LEA AX,[BP-10e], PUSH AX. No claim that old truncated exploratory second-frame disassembly establishes a complete frame. Native raw instruction/p-code observations are authoritative; any decompiled C remains analysis output, not historical-source or exact alias/memory proof.\n");
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler must open Program");
            for (Function function : new Function[] { helper, caller }) {
                var result = decompiler.decompileFunction(function, 60, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Native decompilation failed: " + result.getErrorMessage());
                if (function == helper) {
                    require(result.getHighFunction().getFunctionPrototype().getExtraPop() == 4, "Decompiler must consume only the four-byte return pop");
                }
                Files.writeString(output.resolve(function == helper ? "helper.c" : "caller.c"), "/* Native analysis output, not historical C or exact memory/alias semantics. */\n" + result.getDecompiledFunction().getC());
                StringBuilder calls = new StringBuilder();
                int matchedCalls = 0;
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    var operation = operations.next();
                    if (operation.getOpcode() == PcodeOp.CALL && operation.getInput(0).getAddress().equals(entry)) {
                        require(operation.getNumInputs() == 4 && operation.getInput(1).getSize() == 4 && operation.getInput(2).getSize() == 4 && operation.getInput(3).getSize() == 2, "Actual caller HighFunction must carry two complete far-address records and a WORD count");
                        matchedCalls++;
                        calls.append(operation.getSeqnum().getTarget()).append(' ').append(operation).append('\n');
                    }
                }
                if (function == caller) {
                    require(matchedCalls == 2, "Complete original caller must contain both evidenced copier calls in its HighFunction");
                    Files.writeString(output.resolve("caller-high-calls.txt"), calls);
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        println("FAR COPY VALIDATION PASS: original 38 bytes/22 instructions; stack destination/source/count; DX:AX record; purge0/shift4/pop4; qualified clobbers; two real calls and ten-byte cleanup; aligned first frame.");
    }

    private void requireFarRecord(ghidra.program.model.data.DataType dataType) {
        require(dataType instanceof Structure, "Far address must be a record");
        Structure record = (Structure) dataType;
        require(record.getName().equals("FarAddress16") && record.getLength() == 4 && record.getNumComponents() == 2 && record.getComponent(0).getOffset() == 0 && record.getComponent(0).getFieldName().equals("offset") && record.getComponent(1).getOffset() == 2 && record.getComponent(1).getFieldName().equals("selector"), "Far address record must preserve offset then selector");
    }

    private Address mapped(long offset) {
        List<Address> mappings = currentProgram.getMemory().locateAddressesForFileOffset(offset);
        require(mappings.size() == 1, "Expected one native file mapping for " + Long.toHexString(offset) + ": " + mappings);
        return mappings.get(0);
    }

    private boolean isRegister(Varnode node, String name) {
        var register = currentProgram.getRegister(name);
        return node.getAddress().equals(register.getAddress()) && node.getSize() == register.getMinimumByteSize();
    }

    private boolean containsRegister(Varnode[] nodes, String name) {
        return Arrays.stream(nodes).anyMatch(node -> isRegister(node, name));
    }

    private void exportInstructions(Path output, AddressSet body) throws Exception {
        StringBuilder listing = new StringBuilder();
        for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
            listing.append(instruction.getAddress()).append(' ').append(HexFormat.of().formatHex(instruction.getBytes())).append(' ').append(instruction).append('\n');
            for (var operation : instruction.getPcode()) {
                listing.append("  PCODE ").append(operation).append('\n');
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
