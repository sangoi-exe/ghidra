// Native original-input check; argument: an existing task-private output directory.
//@category LegacyToolchains

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import dev.sangoi.ghidra.legacy.BorlandMemsetAnalyzer;
import dev.sangoi.ghidra.legacy.BorlandSetmemAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class ValidateMemoryFill extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        require("New Executable (NE)".equals(currentProgram.getExecutableFormat()), "Primary evidence requires the native NE loader");
        Address internalEntry = mapped(0x19f2);
        Address wrapperEntry = mapped(0x1a1a);
        Function internal = currentProgram.getFunctionManager().getFunctionAt(internalEntry);
        Function wrapper = currentProgram.getFunctionManager().getFunctionAt(wrapperEntry);
        require(internal != null && BorlandSetmemAnalyzer.CONVENTION.equals(internal.getCallingConventionName()), "Installed automatic setmem analyzer must recognize original input");
        require(wrapper != null && BorlandMemsetAnalyzer.CONVENTION.equals(wrapper.getCallingConventionName()), "Installed automatic memset analyzer must recognize original input");
        requireBytes(0x19f2, "45558bec571e078b7e068b4e088a460a8ae0fcf7c701007404e309aa49d1e9f3ab7301aa5f5d4dcb");
        requireBytes(0x1a1a, "45558bec568b76068a460850ff760a560ee8c4ff83c4068bc65e5d4dcb");
        validateTargetContext(output, internalEntry);
        requireBody(internal, 40, 24);
        requireBody(wrapper, 29, 17);
        requireContract(internal, new String[] { "destination_offset", "byte_count", "fill_word_low_byte" });
        requireContract(wrapper, new String[] { "destination_offset", "value_word_low_byte", "byte_count" });
        int version = SpecExtension.getVersionCounter(currentProgram);
        String internalComment = internal.getComment();
        String wrapperComment = wrapper.getComment();
        MessageLog log = new MessageLog();
        require(new BorlandSetmemAnalyzer().added(currentProgram, internal.getBody(), monitor, log), "Internal rerun failed: " + log);
        require(new BorlandMemsetAnalyzer().added(currentProgram, wrapper.getBody(), monitor, log), "Wrapper rerun failed: " + log);
        require(SpecExtension.getVersionCounter(currentProgram) == version && internalComment.equals(internal.getComment()) && wrapperComment.equals(wrapper.getComment()), "Unchanged rerun must neither reinstall native prototypes nor duplicate comments");

        requireBytes(0x1a2a, "0ee8c4ff83c4068bc6");
        requireCall(0x1a2b, internalEntry);
        requireFarFrame(0x1a2a, 0x1a2b, 0x1a19);
        requireBytes(0x25e7, "b804005033c050ff36b82b900ee823f483c406b80300");
        AddressSet outerWindow = new AddressSet(mapped(0x25e7), mapped(0x25fc));
        DisassembleCommand disassembly = new DisassembleCommand(outerWindow.getMinAddress(), outerWindow, true);
        disassembly.enableCodeAnalysis(false);
        require(disassembly.applyTo(currentProgram, monitor), "Actual outer call window must disassemble natively");
        requireCall(0x25f4, wrapperEntry);
        requireFarFrame(0x25f3, 0x25f4, 0x1a36);
        require(currentProgram.getListing().getInstructionAt(mapped(0x25f7)).getMnemonicString().equals("ADD"), "Actual caller must remove six argument bytes after wrapper return");
        require(currentProgram.getListing().getInstructionAt(mapped(0x25fa)).getMnemonicString().equals("MOV"), "Actual caller overwrites AX with 3 rather than consuming the wrapper result");
        exportInstructions(output.resolve("internal-instructions-pcode.txt"), internal.getBody());
        exportInstructions(output.resolve("wrapper-instructions-pcode.txt"), wrapper.getBody());
        exportInstructions(output.resolve("outer-window-instructions-pcode.txt"), outerWindow);

        StringBuilder contracts = new StringBuilder("Ghidra " + getGhidraVersion() + "\n");
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler must open Program");
            for (Function function : new Function[] { internal, wrapper }) {
                var prototype = function.getCallingConvention();
                contracts.append(function.getEntryPoint()).append(' ').append(function.getPrototypeString(true, true)).append("\nreturn=").append(function.getReturn().getVariableStorage()).append(" purge=").append(function.getStackPurgeSize()).append(" shift=").append(prototype.getStackshift()).append(" pop=").append(prototype.getExtrapop()).append("\nunaffected=").append(Arrays.toString(prototype.getUnaffectedList())).append("\nkilledbycall=").append(Arrays.toString(prototype.getKilledByCallList())).append('\n');
                for (var parameter : function.getParameters()) {
                    contracts.append(parameter.getName()).append(' ').append(parameter.getDataType().getPathName()).append(' ').append(parameter.getVariableStorage()).append('\n');
                }
                contracts.append(function.getComment()).append('\n');
                var result = decompiler.decompileFunction(function, 60, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Native decompilation failed: " + result.getErrorMessage());
                require(result.getHighFunction().getFunctionPrototype().getExtraPop() == 4, "Decompiler must consume only far return4, not caller arguments");
                Files.writeString(output.resolve(function == internal ? "internal.c" : "wrapper.c"), "/* Native analysis output, not historical C or exact memory/alias semantics. */\n" + result.getDecompiledFunction().getC());
                if (function == wrapper) {
                    StringBuilder calls = new StringBuilder();
                    int matchedCalls = 0;
                    var operations = result.getHighFunction().getPcodeOps();
                    while (operations.hasNext()) {
                        var operation = operations.next();
                        if (operation.getOpcode() == PcodeOp.CALL && operation.getInput(0).getAddress().equals(internalEntry)) {
                            require(operation.getNumInputs() == 4 && operation.getInput(1).getSize() == 2 && operation.getInput(2).getSize() == 2 && operation.getInput(3).getSize() == 2, "Actual wrapper HighFunction must carry destination/count/fill WORDs");
                            // Raw CALL 122b writes its return WORD at entry SP-14. Formal +4/+6/+8 must read the SS-qualified argument slots written at SP-10/-8/-6, not unrelated abstract stack inputs.
                            for (int slot = 1; slot <= 3; slot++) {
                                requireActualStackArgument(operation.getInput(slot), 0xfff4 + 2 * slot, calls);
                            }
                            matchedCalls++;
                            calls.append(operation.getSeqnum().getTarget()).append(' ').append(operation).append('\n');
                        }
                    }
                    require(matchedCalls == 1, "Actual wrapper must retain its literal call to the internal fill body");
                    Files.writeString(output.resolve("wrapper-high-call.txt"), calls);
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        Files.writeString(output.resolve("contracts.txt"), contracts.append(log));
        Files.writeString(output.resolve("qualification.txt"), "Original SCRANTIC.EXE file [19f2,1a37), NE1 [11f2,1237): 40-byte/24-instruction internal body plus 29-byte/17-instruction wrapper; exact CWM 3.1 MEMSET member correspondence only, not exclusive release or historical C. Wrapper PUSH CS/near CALL 122b -> 11f2 and inner RETF form a four-byte return frame; ADD SP,6 cleans inner arguments. Actual outer window file [25e7,25fd), NE1 [1de7,1dfd), includes PUSH CS/near CALL 1df4 -> 121a, ADD SP,6, then AX=3. It proves six caller-owned bytes, not consumed wrapper AX or complete outer-procedure semantics. AX results remain WORD register observations. No call-fixup, computed-postcall injection, host pointer, universal alias/memory/fault/source-domain semantics or program execution is claimed. Native C is analysis output; raw instructions/p-code own the observed frame and memory mechanics.\n");

        // This protects the established local priority contract; it is not external ABI evidence.
        for (Function function : new Function[] { internal, wrapper }) {
            function.setName(function == internal ? "user_owned_setmem" : "user_owned_memset", SourceType.USER_DEFINED);
            function.setCallingConvention("__stdcall16far");
            function.setSignatureSource(SourceType.USER_DEFINED);
            function.setComment("user-owned fill contract");
        }
        require(new BorlandSetmemAnalyzer().added(currentProgram, internal.getBody(), monitor, log), "Internal user-ownership rerun failed");
        require(new BorlandMemsetAnalyzer().added(currentProgram, wrapper.getBody(), monitor, log), "Wrapper user-ownership rerun failed");
        for (Function function : new Function[] { internal, wrapper }) {
            require(function.getSignatureSource() == SourceType.USER_DEFINED && function.getCallingConventionName().equals("__stdcall16far") && function.getSymbol().getSource() == SourceType.USER_DEFINED && function.getComment().equals("user-owned fill contract"), "Higher-priority user contract must survive analyzer rerun");
        }
        require(SpecExtension.getVersionCounter(currentProgram) == version, "User-owned functions must not reinstall conventions");
        Files.writeString(output.resolve("ownership-rerun.txt"), log.toString());
        println("MEMORY FILL VALIDATION PASS: automatic original 40/24 and 29/17 matches; internal target operand/address context rejection and normal family control; WORD offsets/results; purge0/shift4/pop4; qualified clobbers; actual PUSHCS/nearCALL/RETF frames and six-byte cleanups; selector-qualified WORD call arguments at near SP-10/-8/-6; native C/p-code; repeat and user ownership retained.");
    }

    private void validateTargetContext(Path output, Address originalEntry) throws Exception {
        byte[] bytes = new byte[69];
        require(currentProgram.getMemory().getBytes(originalEntry, bytes) == bytes.length, "Expected the complete original fill family for target-context fixtures");
        int[] lengths = { 1, 1, 2, 1, 1, 1, 3, 3, 3, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 3, 3, 1, 3, 1, 1, 3, 3, 2, 1, 1, 1, 1 };
        StringBuilder evidence = new StringBuilder("Production helper owner: " + BorlandSetmemAnalyzer.class.getProtectionDomain().getCodeSource().getLocation() + "\n");
        List<String> incompatibleContracts = new ArrayList<>();
        for (String scenario : new String[] { "normal", "opsize", "addrsize" }) {
            ProgramDB fixture = new ProgramDB("Fill target context " + scenario, currentProgram.getLanguage(), currentProgram.getLanguage().getDefaultCompilerSpec(), this);
            int transaction = fixture.startTransaction("Predecoded fill target context witness");
            try {
                Address entry = fixture.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000);
                Address end = entry.add(bytes.length - 1);
                Address wrapperEntry = entry.add(40);
                Address target = entry.add(31);
                var block = fixture.getMemory().createInitializedBlock("fill-family", entry, bytes.length, (byte) 0, monitor, false);
                block.setExecute(true);
                fixture.getMemory().setBytes(entry, bytes);
                Address address = entry;
                // Decode each bounded instruction separately: entry disassembly can otherwise normalize flowing context.
                for (int length : lengths) {
                    Address instructionEnd = address.add(length - 1);
                    for (String name : new String[] { "opsize", "addrsize" }) {
                        BigInteger value = address.equals(target) && scenario.equals(name) ? BigInteger.ONE : BigInteger.ZERO;
                        fixture.getProgramContext().setValue(fixture.getRegister(name), address, instructionEnd, value);
                    }
                    DisassembleCommand command = new DisassembleCommand(address, new AddressSet(address, instructionEnd), false);
                    command.enableCodeAnalysis(false);
                    require(command.applyTo(fixture, monitor), "Native target-context fixture disassembly failed: " + scenario + " at " + address);
                    Instruction instruction = fixture.getListing().getInstructionAt(address);
                    require(instruction != null && instruction.getLength() == length, "Target-context witness must retain the qualified instruction lengths: " + scenario);
                    address = address.add(length);
                }
                require(address.equals(end.next()), "Target-context fixture must decode the complete 69-byte family");
                for (String name : new String[] { "opsize", "addrsize" }) {
                    require(BigInteger.ZERO.equals(fixture.getProgramContext().getValue(fixture.getRegister(name), entry, false)) && BigInteger.ZERO.equals(fixture.getProgramContext().getValue(fixture.getRegister(name), wrapperEntry, false)), "Both helper entries must remain in 16-bit context: " + scenario);
                    BigInteger expected = scenario.equals(name) ? BigInteger.ONE : BigInteger.ZERO;
                    require(expected.equals(fixture.getProgramContext().getValue(fixture.getRegister(name), target, false)), "Internal target-context witness was not established: " + scenario);
                }
                Instruction instruction = fixture.getListing().getInstructionAt(target);
                String decoded = instruction.toString();
                PcodeOp[] operations = instruction.getPcode();
                int storeSize = scenario.equals("opsize") ? 4 : 2;
                require(Arrays.stream(operations).anyMatch(operation -> operation.getOpcode() == PcodeOp.STORE && operation.getInput(2).getSize() == storeSize), "Native fill STORE width must reflect internal operand context: " + scenario);
                for (String name : scenario.equals("addrsize") ? new String[] { "EDI", "ECX" } : new String[] { "DI", "CX" }) {
                    var register = fixture.getRegister(name);
                    require(Arrays.stream(operations).anyMatch(operation -> operation.getOutput() != null && operation.getOutput().getAddress().equals(register.getAddress()) && operation.getOutput().getSize() == register.getMinimumByteSize()), "Native fill index/count must reflect internal address context: " + scenario + " " + name);
                }
                evidence.append(scenario).append(" entries=0/0 internal=").append(scenario.equals("opsize") ? 1 : 0).append('/').append(scenario.equals("addrsize") ? 1 : 0).append(' ').append(decoded).append(" length=").append(instruction.getLength()).append('\n');
                for (PcodeOp operation : operations) {
                    evidence.append("  PCODE ").append(operation).append('\n');
                }
                MessageLog log = new MessageLog();
                int version = SpecExtension.getVersionCounter(fixture);
                require(new BorlandSetmemAnalyzer().added(fixture, new AddressSet(entry, wrapperEntry.previous()), monitor, log), "Production internal target-context analysis failed: " + log);
                boolean wrapperOk = new BorlandMemsetAnalyzer().added(fixture, new AddressSet(wrapperEntry, end), monitor, log);
                Function internal = fixture.getFunctionManager().getFunctionAt(entry);
                Function wrapper = fixture.getFunctionManager().getFunctionAt(wrapperEntry);
                evidence.append("internalContract=").append(internal == null ? "none" : internal.getCallingConventionName()).append(" wrapperResult=").append(wrapperOk).append(" wrapperFunction=").append(wrapper == null ? "none" : wrapper.getName()).append(" wrapperContract=").append(wrapper == null ? "none" : wrapper.getCallingConventionName()).append(" prototypeVersion=").append(version).append("->").append(SpecExtension.getVersionCounter(fixture)).append('\n').append(log).append('\n');
                if (scenario.equals("normal")) {
                    require(wrapperOk && internal != null && BorlandSetmemAnalyzer.CONVENTION.equals(internal.getCallingConventionName()) && wrapper != null && BorlandMemsetAnalyzer.CONVENTION.equals(wrapper.getCallingConventionName()), "Normal complete native fill family must receive both contracts");
                }
                else {
                    require(internal == null, "Shared qualification must reject the incompatible internal helper: " + scenario);
                    if (wrapper != null && BorlandMemsetAnalyzer.CONVENTION.equals(wrapper.getCallingConventionName())) {
                        incompatibleContracts.add(scenario);
                    }
                }
                require(fixture.getListing().getInstructionAt(target).toString().equals(decoded) && Arrays.toString(fixture.getListing().getInstructionAt(target).getPcode()).equals(Arrays.toString(operations)), "Analyzers must preserve the decoded target-context witness: " + scenario);
            }
            finally {
                fixture.endTransaction(transaction, false);
                fixture.release(this);
            }
        }
        Files.writeString(output.resolve("target-context.txt"), evidence);
        require(incompatibleContracts.isEmpty(), "Incompatible internal target context must not receive the operational wrapper contract: " + incompatibleContracts);
    }

    private void requireActualStackArgument(Varnode argument, long expectedOffset, StringBuilder evidence) {
        PcodeOp load = argument.getDef();
        while (load != null && (load.getOpcode() == PcodeOp.COPY || load.getOpcode() == PcodeOp.CAST) && load.getInput(0).getSize() == 2) {
            load = load.getInput(0).getDef();
        }
        require(load != null && load.getOpcode() == PcodeOp.LOAD && load.getOutput().getSize() == 2, "Actual stack argument must be a WORD memory read, not an unrelated abstract stack Varnode");
        Varnode address = load.getInput(1);
        while (address.getDef() != null && address.getDef().getOpcode() == PcodeOp.CAST) {
            address = address.getDef().getInput(0);
        }
        PcodeOp segment = address.getDef();
        require(address.getSize() == 4 && segment != null && segment.getOpcode() == PcodeOp.SEGMENTOP, "Actual argument LOAD must retain its segmented address");
        require(isRegister(segment.getInput(1), "SS") && segment.getInput(1).isInput(), "Actual wrapper argument must use the unchanged SS operand established by its raw stack accesses");
        Varnode near = segment.getInput(2);
        long offset = 0;
        while (near.getDef() != null) {
            PcodeOp expression = near.getDef();
            if ((expression.getOpcode() == PcodeOp.COPY || expression.getOpcode() == PcodeOp.CAST) && expression.getInput(0).getSize() == 2) {
                near = expression.getInput(0);
            }
            else if ((expression.getOpcode() == PcodeOp.INT_ADD || expression.getOpcode() == PcodeOp.PTRSUB) && expression.getInput(1).isConstant()) {
                offset += expression.getInput(1).getOffset();
                near = expression.getInput(0);
            }
            else {
                break;
            }
        }
        require(segment.getInput(2).getSize() == 2 && near.getSize() == 2 && isRegister(near, "SP") && near.isInput() && (offset & 0xffff) == expectedOffset, "Actual argument displacement must wrap in the two-byte near SP domain before segmentation");
        evidence.append("argument read: ").append(load).append("; ").append(segment).append("; entry SP delta=0x").append(Long.toHexString(offset & 0xffff)).append('\n');
    }

    private void requireContract(Function function, String[] names) {
        require(function.hasCustomVariableStorage() && function.getStackPurgeSize() == 0 && function.getCallFixup() == null, "Fill contract must be explicit storage, purge0, no invented effect fixup");
        var parameters = function.getParameters();
        require(parameters.length == 3, "Exactly three stack WORD inputs, no GPR arguments");
        for (int i = 0; i < 3; i++) {
            require(parameters[i].getName().equals(names[i]) && parameters[i].isStackVariable() && parameters[i].getStackOffset() == 4 + 2 * i && parameters[i].getLength() == 2 && parameters[i].getDataType().getName().equals("ushort"), "Wrong stack WORD input " + names[i]);
        }
        Varnode[] returned = function.getReturn().getVariableStorage().getVarnodes();
        require(function.getReturnType().getName().equals("ushort") && returned.length == 1 && isRegister(returned[0], "AX"), "Result must be AX WORD, never a host pointer");
        var prototype = function.getCallingConvention();
        require(prototype.getStackshift() == 4 && prototype.getExtrapop() == 4, "Plain far return must pop4, not arguments");
        for (String name : new String[] { "BX", "DX", "BP", "SI", "DI", "DS", "SS" }) {
            require(containsRegister(prototype.getUnaffectedList(), name), "Missing qualified low16 preservation " + name);
        }
        for (String name : new String[] { "AX", "CX", "ES", "DF", "CF", "PF", "AF", "ZF", "SF", "OF" }) {
            require(!containsRegister(prototype.getUnaffectedList(), name) && containsRegister(prototype.getKilledByCallList(), name), "Unsupported preservation or missing clobber " + name);
        }
    }

    private void requireBody(Function function, int length, int count) {
        require(function.getBody().getNumAddresses() == length, "Body must retain the complete original byte extent");
        int actual = 0;
        for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            actual++;
        }
        require(actual == count, "Native instruction count differs from original body");
    }

    private void requireFarFrame(long pushOffset, long callOffset, long returnOffset) {
        Instruction push = currentProgram.getListing().getInstructionAt(mapped(pushOffset));
        Instruction call = currentProgram.getListing().getInstructionAt(mapped(callOffset));
        Instruction farReturn = currentProgram.getListing().getInstructionAt(mapped(returnOffset));
        require(push != null && call != null && farReturn != null, "Native far-compatible frame instructions must exist");
        // Native push22 snapshots CS into a unique temporary before decrementing SP and storing it.
        Varnode selector = Arrays.stream(push.getPcode()).filter(op -> op.getOpcode() == PcodeOp.COPY && isRegister(op.getInput(0), "CS")).map(PcodeOp::getOutput).findFirst().orElse(null);
        require(selector != null && Arrays.stream(push.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.STORE && op.getInput(2).equals(selector)) && stackAdjustments(push, PcodeOp.INT_SUB) == 1, "Actual PUSH CS must snapshot/store the selector and decrement SP by two");
        require(Arrays.stream(call.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.CALL) && stackAdjustments(call, PcodeOp.INT_SUB) == 1, "Actual near CALL must push a two-byte return offset and remain a native CALL");
        require(Arrays.stream(farReturn.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.RETURN) && Arrays.stream(farReturn.getPcode()).anyMatch(op -> op.getOutput() != null && isRegister(op.getOutput(), "CS")) && stackAdjustments(farReturn, PcodeOp.INT_ADD) == 2, "Actual RETF must restore CS, pop two WORDs and perform a native RETURN");
    }

    private long stackAdjustments(Instruction instruction, int opcode) {
        return Arrays.stream(instruction.getPcode()).filter(op -> op.getOpcode() == opcode && isRegister(op.getOutput(), "SP") && op.getInput(1).isConstant() && op.getInput(1).getOffset() == 2).count();
    }

    private void requireCall(long offset, Address target) {
        var call = currentProgram.getListing().getInstructionAt(mapped(offset));
        require(call != null && call.getFlowType().isCall() && Arrays.asList(call.getFlows()).contains(target), "Original near CALL must resolve to qualified target at file " + Long.toHexString(offset));
    }

    private void requireBytes(long offset, String expected) throws Exception {
        byte[] bytes = new byte[expected.length() / 2];
        require(currentProgram.getMemory().getBytes(mapped(offset), bytes) == bytes.length && HexFormat.of().formatHex(bytes).equals(expected), "Original bytes differ at file " + Long.toHexString(offset));
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

    private void exportInstructions(Path output, ghidra.program.model.address.AddressSetView body) throws Exception {
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
