// Native original-input check; arguments: an existing task-private output directory.
//@category LegacyToolchains

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import dev.sangoi.ghidra.legacy.BorlandFarCopyAnalyzer;
import dev.sangoi.ghidra.legacy.BorlandFmemmoveAnalyzer;
import dev.sangoi.ghidra.legacy.BorlandFmovmemAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
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
        validateMoveFamily(output);
        println("FAR COPY VALIDATION PASS: original 38 bytes/22 instructions; stack destination/source/count; DX:AX record; purge0/shift4/pop4; qualified clobbers; two real calls and ten-byte cleanup; aligned first frame.");
    }

    private void validateMoveFamily(Path output) throws Exception {
        Address coreEntry = mapped(0x32e8);
        Address wrapperEntry = mapped(0x3341);
        AddressSet family = new AddressSet(coreEntry, mapped(0x3367));
        byte[] bytes = new byte[128];
        require(currentProgram.getMemory().getBytes(coreEntry, bytes) == 128 && HexFormat.of().formatHex(bytes).equals("45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb"), "Whole original move family must agree, not just one helper");
        Function core = currentProgram.getFunctionManager().getFunctionAt(coreEntry);
        Function wrapper = currentProgram.getFunctionManager().getFunctionAt(wrapperEntry);
        require(core != null && BorlandFmovmemAnalyzer.CONVENTION.equals(core.getCallingConventionName()), "Automatic production analysis must recognize the complete original move core");
        require(wrapper != null && BorlandFmemmoveAnalyzer.CONVENTION.equals(wrapper.getCallingConventionName()), "Automatic production analysis must recognize the complete original move wrapper");
        int[][] lengths = {
            { 1, 1, 2, 1, 1, 1, 3, 3, 3, 3, 2, 2, 2, 2, 2, 1, 3, 2, 1, 2, 3, 3, 3, 2, 2, 2, 1, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 },
            { 1, 1, 2, 1, 1, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 1, 1, 1, 1, 1 }
        };
        Function[] helpers = { core, wrapper };
        StringBuilder report = new StringBuilder("Ghidra " + getGhidraVersion() + "\nWhole original family FILE[32e8,3368), distinct core89/49 and wrapper39/20.\n");
        for (int i = 0; i < helpers.length; i++) {
            Function function = helpers[i];
            Address entry = function.getEntryPoint();
            int size = i == 0 ? 89 : 39;
            require(function.getBody().equals(new AddressSet(entry, entry.add(size - 1))), "Complete native move bodies must be distinct, exact and nonoverlapping");
            Address address = entry;
            for (int length : lengths[i]) {
                var instruction = currentProgram.getListing().getInstructionAt(address);
                require(instruction != null && instruction.getLength() == length, "Incorrect move instruction boundary at " + address);
                for (String name : new String[] { "opsize", "addrsize" }) {
                    require(BigInteger.ZERO.equals(currentProgram.getProgramContext().getValue(currentProgram.getRegister(name), address, false)), "Move instruction has non-16-bit context at " + address);
                }
                address = address.add(length);
            }
            require(address.equals(entry.add(size)), "Move instruction coverage must end exactly at body boundary");
            require(function.hasCustomVariableStorage() && function.getStackPurgeSize() == 0 && function.getCallFixup() == null, "Move contracts must retain caller arguments without invented memory-effect fixups");
            var parameters = function.getParameters();
            require(parameters.length == 3, "Move has only two far-address records and a WORD count");
            String[] names = i == 0 ? new String[] { "source", "destination", "byte_count" } : new String[] { "destination", "source", "byte_count" };
            for (int j = 0; j < parameters.length; j++) {
                var parameter = parameters[j];
                require(parameter.getName().equals(names[j]) && parameter.isStackVariable() && parameter.getStackOffset() == 4 + j * 4 && parameter.getLength() == (j == 2 ? 2 : 4), "Wrong move entry-stack argument " + names[j]);
                if (j < 2) {
                    requireFarRecord(parameter.getDataType());
                }
                report.append(parameter.getName()).append(' ').append(parameter.getDataType().getPathName()).append(' ').append(parameter.getVariableStorage()).append('\n');
            }
            var prototype = function.getCallingConvention();
            require(prototype.getStackshift() == 4 && prototype.getExtrapop() == 4, "Move RETF must consume only its four-byte return, not arguments");
            for (String name : new String[] { "BP", "SI", "DI", "DS", "SS" }) {
                require(containsRegister(prototype.getUnaffectedList(), name), "Missing qualified move preservation " + name);
            }
            for (String name : new String[] { "BX", "AX", "DX", "CX", "ES", "DF", "CF", "PF", "AF", "ZF", "SF", "OF" }) {
                require(!containsRegister(prototype.getUnaffectedList(), name) && containsRegister(prototype.getKilledByCallList(), name), "Missing conservative move clobber " + name);
            }
            require(currentProgram.getListing().getInstructionAt(entry.add(size - 1)).getMnemonicString().equals("RETF"), "Move helper must terminate in plain native RETF");
            report.append(function.getPrototypeString(true, true)).append("\nreturn=").append(function.getReturn().getVariableStorage()).append(" purge0/shift4/pop4\nunaffected=").append(Arrays.toString(prototype.getUnaffectedList())).append("\nkilledbycall=").append(Arrays.toString(prototype.getKilledByCallList())).append('\n').append(function.getComment()).append('\n');
        }
        require(core.getReturnType() instanceof VoidDataType && core.getReturn().getVariableStorage().isVoidStorage(), "Move core has an explicit void analysis return");
        requireFarRecord(wrapper.getReturnType());
        Varnode[] returned = wrapper.getReturn().getVariableStorage().getVarnodes();
        require(returned.length == 2 && isRegister(returned[0], "DX") && isRegister(returned[1], "AX"), "Move wrapper result must be full selector DX then offset AX");
        var pushCs = currentProgram.getListing().getInstructionAt(wrapperEntry.add(21));
        var innerCall = currentProgram.getListing().getInstructionAt(wrapperEntry.add(22));
        require(pushCs != null && pushCs.getMnemonicString().equals("PUSH") && pushCs.getDefaultOperandRepresentation(0).equals("CS"), "Move wrapper must PUSH CS for the actual far-compatible frame");
        require(innerCall != null && innerCall.getLength() == 3 && innerCall.getFlowType().isCall() && Arrays.equals(innerCall.getFlows(), new Address[] { coreEntry }), "Actual native near CALL must resolve to the distinct core");
        require(HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(wrapperEntry.add(25)).getBytes()).equals("83c40a"), "Move wrapper must clean five inner WORD arguments");
        require(HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(wrapperEntry.add(28)).getBytes()).equals("8b5608") && HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(wrapperEntry.add(31)).getBytes()).equals("8b4606"), "Wrapper must freshly load destination selector then offset after the call");
        exportInstructions(output.resolve("move-family-instructions-pcode.txt"), family);

        Address callerEntry = mapped(0x50308);
        AddressSet callerBody = new AddressSet(callerEntry, mapped(0x5033d));
        DisassembleCommand command = new DisassembleCommand(callerEntry, callerBody, true);
        command.enableCodeAnalysis(false);
        require(command.applyTo(currentProgram, monitor), "Complete original move caller disassembly failed");
        Function caller = currentProgram.getFunctionManager().getFunctionAt(callerEntry);
        if (caller == null) {
            caller = currentProgram.getFunctionManager().createFunction("qualified_far_move_caller", callerEntry, callerBody, SourceType.ANALYSIS);
        }
        var call = currentProgram.getListing().getInstructionAt(mapped(0x5032a));
        require(call != null && call.getLength() == 5 && call.getFlowType().isCall() && Arrays.equals(call.getFlows(), new Address[] { wrapperEntry }), "Actual original NE67:0d2a relocation must bind wrapper NE1:1141, not core NE1:10e8");
        require(HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(mapped(0x5032f)).getBytes()).equals("83c40a"), "Original outer move caller must clean ten argument bytes");
        require(HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(mapped(0x50332)).getBytes()).equals("8b5608") && HexFormat.of().formatHex(currentProgram.getListing().getInstructionAt(mapped(0x50335)).getBytes()).equals("8b4606"), "Original caller freshly reloads its own destination pair instead of consuming the wrapper result");
        require(currentProgram.getListing().getInstructionAt(mapped(0x5033d)).getMnemonicString().equals("RETF"), "Original move caller must end at its own plain far return");
        byte[] frame = new byte[23];
        require(currentProgram.getMemory().getBytes(mapped(0x50313), frame) == frame.length && HexFormat.of().formatHex(frame).equals("57c45e06268a0798508b460640ff760850ff7608ff7606"), "Original caller must sign-extend byte count, increment only source offset and independently refresh both address pairs");
        exportInstructions(output.resolve("move-caller-instructions-pcode.txt"), callerBody);
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native move decompiler must open Program");
            for (Function function : new Function[] { core, wrapper, caller }) {
                var result = decompiler.decompileFunction(function, 60, monitor);
                require(result.decompileCompleted() && result.getHighFunction() != null, "Native move decompilation failed: " + result.getErrorMessage());
                if (function != caller) {
                    require(result.getHighFunction().getFunctionPrototype().getExtraPop() == 4, "Qualified move decompiler must retain four-byte far return pop");
                }
                String stem;
                if (function == core) {
                    stem = "fmovmem";
                }
                else if (function == wrapper) {
                    stem = "fmemmove";
                }
                else {
                    stem = "move-caller";
                }
                Files.writeString(output.resolve(stem + ".c"), "/* Static native analysis, not historical C, selector resolution or fault/alias safety. */\n" + result.getDecompiledFunction().getC());
                Address target = function == wrapper ? coreEntry : wrapperEntry;
                int matched = 0;
                StringBuilder calls = new StringBuilder();
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    var operation = operations.next();
                    if (operation.getOpcode() == PcodeOp.CALL && operation.getInput(0).getAddress().equals(target)) {
                        require(operation.getNumInputs() == 4 && operation.getInput(1).getSize() == 4 && operation.getInput(2).getSize() == 4 && operation.getInput(3).getSize() == 2, "Move native HighFunction call requires two far records and WORD count");
                        if (function == wrapper) {
                            require(operation.getOutput() == null, "Source-first core call must not invent a destination result");
                        }
                        matched++;
                        calls.append(operation.getSeqnum().getTarget()).append(' ').append(operation).append('\n');
                    }
                }
                if (function != core) {
                    require(matched == 1, "Expected exactly one evidenced move call in " + stem);
                    Files.writeString(output.resolve(stem + "-high-calls.txt"), calls);
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        int version = SpecExtension.getVersionCounter(currentProgram);
        String coreComment = core.getComment();
        String wrapperComment = wrapper.getComment();
        MessageLog log = new MessageLog();
        require(new BorlandFmemmoveAnalyzer().added(currentProgram, family, monitor, log) && new BorlandFmovmemAnalyzer().added(currentProgram, family, monitor, log), "Move repeat failed: " + log);
        require(SpecExtension.getVersionCounter(currentProgram) == version && coreComment.equals(core.getComment()) && wrapperComment.equals(wrapper.getComment()), "Unchanged move analysis must not reinstall prototypes or duplicate comments");
        validateMoveContext(output, bytes, lengths);
        for (Function function : helpers) {
            function.setName(function == core ? "user_move_core" : "user_move_wrapper", SourceType.USER_DEFINED);
            function.setSignatureSource(SourceType.USER_DEFINED);
            function.setStackPurgeSize(6);
            function.setComment("User-owned move contract");
        }
        require(new BorlandFmovmemAnalyzer().added(currentProgram, family, monitor, log) && new BorlandFmemmoveAnalyzer().added(currentProgram, family, monitor, log), "User-owned move repeat failed: " + log);
        for (Function function : helpers) {
            require(function.getSignatureSource() == SourceType.USER_DEFINED && function.getName().startsWith("user_move_") && function.getStackPurgeSize() == 6 && function.getComment().equals("User-owned move contract"), "Manual move name/signature/purge/comment must survive recognition");
        }
        report.append("Original NE67:[0d08,0d3e), FILE[50308,5033e): actual native relocation targets wrapper; ADD SP,0a; caller freshly rereads its destination pair, not a consumed wrapper result. Whole-family qualification is independent of labels and analyzer order. Repeat stable; user-owned contracts preserved. Static native observations do not establish original execution or unrestricted memmove semantics.\n").append(log);
        Files.writeString(output.resolve("move-contract.txt"), report);
        println("FAR MOVE VALIDATION PASS: automatic original whole128 qualification; distinct core89/49 void and wrapper39/20 DX:AX FarAddress16; source/destination argument order, purge0/shift4/pop4; BX/flags/DF clobbers; actual PUSHCS/nearCALL/RETF and original far caller; native C/High/p-code; changed internal wrapper context rejects both contracts; repeat/manual retention.");
    }

    private void validateMoveContext(Path output, byte[] bytes, int[][] lengths) throws Exception {
        ProgramDB fixture = new ProgramDB("Move family internal wrapper context", currentProgram.getLanguage(), currentProgram.getLanguage().getDefaultCompilerSpec(), this);
        int transaction = fixture.startTransaction("Native whole-family qualification witness");
        try {
            Address entry = fixture.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000);
            Address end = entry.add(127);
            var block = fixture.getMemory().createInitializedBlock("move_family", entry, 128, (byte) 0, monitor, false);
            block.setExecute(true);
            fixture.getMemory().setBytes(entry, bytes);
            Address address = entry;
            for (int[] body : lengths) {
                for (int length : body) {
                    Address instructionEnd = address.add(length - 1);
                    fixture.getProgramContext().setValue(fixture.getRegister("opsize"), address, instructionEnd, address.equals(entry.add(117)) ? BigInteger.ONE : BigInteger.ZERO);
                    fixture.getProgramContext().setValue(fixture.getRegister("addrsize"), address, instructionEnd, BigInteger.ZERO);
                    DisassembleCommand command = new DisassembleCommand(address, new AddressSet(address, instructionEnd), false);
                    command.enableCodeAnalysis(false);
                    require(command.applyTo(fixture, monitor), "Move context witness failed to decode at " + address);
                    require(fixture.getListing().getInstructionAt(address).getLength() == length, "Move context witness must preserve instruction boundaries");
                    address = address.add(length);
                }
            }
            var changed = fixture.getListing().getInstructionAt(entry.add(117));
            require(Arrays.stream(changed.getPcode()).anyMatch(operation -> operation.getOpcode() == PcodeOp.LOAD && operation.getOutput().getSize() == 4), "Internal wrapper MOV must demonstrably load DWORD under changed native context");
            require(BigInteger.ZERO.equals(fixture.getProgramContext().getValue(fixture.getRegister("opsize"), entry, false)), "Move core entry must retain 16-bit context");
            require(Arrays.equals(fixture.getListing().getInstructionAt(entry.add(111)).getFlows(), new Address[] { entry }), "Context witness must retain the actual native near CALL target");
            MessageLog log = new MessageLog();
            AddressSet family = new AddressSet(entry, end);
            require(!new BorlandFmovmemAnalyzer().added(fixture, family, monitor, log), "Core must reject its neighboring wrapper's incompatible internal context");
            require(log.toString().contains("Move wrapper has unqualified native instruction boundaries or 16-bit context"), "The changed wrapper context, not a different fixture prerequisite, must cause the transitive rejection");
            require(new BorlandFmemmoveAnalyzer().added(fixture, family, monitor, log), "Wrapper recognition must cleanly reject its own incompatible context");
            Function core = fixture.getFunctionManager().getFunctionAt(entry);
            Function wrapper = fixture.getFunctionManager().getFunctionAt(entry.add(89));
            require((core == null || !BorlandFmovmemAnalyzer.CONVENTION.equals(core.getCallingConventionName())) && (wrapper == null || !BorlandFmemmoveAnalyzer.CONVENTION.equals(wrapper.getCallingConventionName())), "Neither helper may acquire its operational contract from an incompletely qualified family");
            Files.writeString(output.resolve("move-internal-context.txt"), "One original-byte native fixture: entry/core context16 intact; wrapper post-call MOV at family+117 has opsize1, same length3 but DWORD load. Both operational contracts rejected; shared transitive qualification reports failed core application, while direct wrapper instruction qualification rejects before application. This protects local whole-family recognition, not external runtime behavior.\n" + changed + "\n" + Arrays.toString(changed.getPcode()) + "\n" + log);
        }
        finally {
            fixture.endTransaction(transaction, false);
            fixture.release(this);
        }
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
