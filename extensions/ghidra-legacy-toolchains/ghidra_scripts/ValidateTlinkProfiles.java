// Exact-image native assertions. Arguments: original path, existing private output directory, direct|automatic, baseline|patched-core.
//@category LegacyToolchains

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.Tlink401Profile;
import dev.sangoi.ghidra.legacy.profiles.Tlink51Profile;
import dev.sangoi.ghidra.legacy.profiles.TlinkWriterContract;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.XmlEncode;

public class ValidateTlinkProfiles extends GhidraScript {
    private ToolchainProfile.Context context;
    private final StringBuilder result = new StringBuilder();
    private static final int[] FAR_CODE_SLOTS = {0xc,0x16,0xbb,0xe3,0xed,0x1ce};
    private static final int[][] ERROR_INTERVALS = { {0xddf9,0xde2f}, {0xde37,0xde42}, {0xde4c,0xde51}, {0xde59,0xdeb5}, {0xdec7,0xded4}, {0xdee0,0xdeec}, {0xdef1,0xdf00}, {0xdf1c,0xdf70} };
    private static final int[][] INLINE_TEXT_JOINS = { {0xde2c,0xde2f,0xde37}, {0xde3f,0xde42,0xde4c}, {0xde4e,0xde51,0xde59}, {0xdeb2,0xdeb5,0xdec7}, {0xded1,0xded4,0xdee0}, {0xdee9,0xdeec,0xdef1}, {0xdefd,0xdf00,0xdf1c} };

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 4 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected original, output, direct|automatic, runtime-label");
        Path output = Path.of(args[1]);
        ToolchainProfile profile = new Tlink51Profile();
        context = profile.match(currentProgram, monitor);
        boolean ne = context != null;
        if (!ne) {
            profile = new Tlink401Profile();
            context = profile.match(currentProgram, monitor);
        }
        require(context != null, "Native loader must retain an exactly qualified TLINK original, not BinaryLoader fallback");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Imported original FileBytes literally equal the named source input");
        long start = ne ? 0x4e0b : 0x3458;
        String name = ne ? "tlink51_rewrite_far_window_cf" : "tlink401_rewrite_far_window_cf";
        var symbol = currentProgram.getSymbolTable().getSymbol(name, context.mapped(start), currentProgram.getGlobalNamespace());
        result.append(profile.id()).append("; Ghidra ").append(getGhidraVersion()).append("; runtime-label=").append(args[3]).append("; activation=").append(args[2]).append("; marker-before=").append(symbol != null).append('\n');
        MessageLog log = new MessageLog();
        if (args[2].equals("automatic")) {
            require(symbol != null, "Automatic activation must have occurred before the validator; never silently apply a missing profile");
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
            result.append("Explicit direct-profile application; not evidence of automatic registry activation.\n");
        }
        Function writer = checkFunction(start, start + 150, 51);
        require(writer.getCallingConventionName().equals(TlinkWriterContract.CONVENTION) && writer.getStackPurgeSize() == 0, "Dedicated near stack model/purge0 required");
        require(writer.getCallingConvention().getExtrapop() == 2 && writer.getCallingConvention().getStackshift() == 2, "Near RET consumes2, not a FAR/unknown4-byte model");
        require(writer.hasCustomVariableStorage() && writer.getReturnType().getLength() == 7 && writer.getReturn().getVariableStorage().toString().equals("ES:2,CX:2,DX:2,CF:1"), "Retain CF/DX/CX/ES joined analysis storage, not AX bool");
        require(writer.getParameterCount() == 4, "Native body input words are explicit analysis inputs, not a void historical C signature");
        String[] inputRegisters = { "BX", "CX", "DX", "DS" };
        for (int i = 0; i < inputRegisters.length; i++) {
            require(writer.getParameter(i).getVariableStorage().getRegister().equals(currentProgram.getRegister(inputRegisters[i])), "Actual custom input register " + inputRegisters[i]);
        }
        require(currentProgram.getProgramContext().getValue(currentProgram.getRegister("DS"), writer.getEntryPoint(), false) == null, "Writer DS is not a caller-qualified loader constant");
        for (String register : new String[] { "ES", "CX", "DX", "CF", "ZF", "PF", "AF", "SF", "OF" }) {
            require(contains(writer.getCallingConvention().getKilledByCallList(), register), "Writer clobber missing: " + register);
            require(!contains(writer.getCallingConvention().getUnaffectedList(), register), "Overstrong preservation of " + register);
        }
        for (String register : new String[] { "AX", "BX", "BP", "SI", "DI", "DS", "SS", "CS", "DF" }) {
            require(contains(writer.getCallingConvention().getUnaffectedList(), register), "Missing established low16 local preservation: " + register);
        }
        checkWriterBody(writer, start, output);
        if (ne) {
            check51();
        }
        else {
            check401();
        }
        int types = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        String before = currentProgram.getListing().getComment(CommentType.PLATE, writer.getEntryPoint());
        if (args[2].equals("automatic")) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analyzer rerun failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }
        require(types == currentProgram.getDataTypeManager().getDataTypeCount(true) && symbols == currentProgram.getSymbolTable().getNumSymbols(), "Repeated application does not duplicate types/symbols");
        require(before.equals(currentProgram.getListing().getComment(CommentType.PLATE, writer.getEntryPoint())), "Repeated application does not duplicate writer qualification");
        result.append(args[2].equals("automatic") ? "Repeated production analyzer native batch: unchanged datatype/symbol counts and writer comment.\n" : "Repeated explicit direct profile application: unchanged datatype/symbol counts and writer comment; automatic batch behavior not proved.\n");
        decompileWriter(writer, output);
        if (ne && args[2].equals("automatic")) {
            checkPatchedFunction51("F1 FAR-slot CALLF", 0x1180c, 0x1180c, 0xea, 0x9a, 17);
            checkPatchedFunction51("F2 shared POP AX", 0xeff9, 0xf00d, 0x5a, 0x58, 37);
            checkPreservedInlinePrerequisite51(0xc6f0, false);
            checkPreservedInlinePrerequisite51(0xc69f, true);
            checkPreservedInlinePrerequisite51(0xeff9, true);
            check51();
            result.append("Restored qualified original after all adverse fixtures: six code slots/99 raw DATA slots, eight-range body/89 inline DATA bytes and seven conditional joins remain intact.\n");
        }
        // As with production facts, keep fixture installation from queuing unrelated native inference.
        String manualName = "user_owned_" + name;
        var ds = currentProgram.getRegister("DS");
        require(AutoAnalysisManager.getAnalysisManager(currentProgram).scheduleWorker(new AnalysisWorker() {
            public String getWorkerName() {
                return "Install manual TLINK writer preservation fixture";
            }
            public boolean analysisWorkerCallback(Program program, Object ignored, TaskMonitor workerMonitor) throws Exception {
                writer.setName(manualName, SourceType.USER_DEFINED);
                writer.setReturnType(UnsignedShortDataType.dataType, SourceType.USER_DEFINED);
                writer.setStackPurgeSize(26);
                currentProgram.getProgramContext().setValue(ds, writer.getEntryPoint(), writer.getBody().getMaxAddress(), BigInteger.valueOf(0x3456));
                return true;
            }
        }, null, false, monitor), "Install manual writer fixture in native suppressed-event worker");
        String manualSignature = writer.getPrototypeString(true, true);
        AddressSet manualBody = new AddressSet(writer.getBody());
        if (args[2].equals("automatic")) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production manual-writer reapplication failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.applyFinalFacts(context, monitor, log);
        }
        require(writer.getSignatureSource() == SourceType.USER_DEFINED && manualSignature.equals(writer.getPrototypeString(true, true)) && manualBody.equals(writer.getBody()) && writer.getStackPurgeSize() == 26, "Higher-priority writer signature/body/purge must not receive dependent writer-contract mutation");
        require(BigInteger.valueOf(0x3456).equals(currentProgram.getProgramContext().getValue(ds, writer.getEntryPoint(), false)), "Preserved writer must retain manual DS instead of dependent contract removal");
        result.append("Manual writer: USER_DEFINED signature/body/purge26 and DS3456 survive reapplication; dependent writer-contract application skipped.\n");
        result.append("No caller-propagation proof, historical C ABI/identity, dynamic selector/code alias, external service/physical-I/O success or debug import claimed. Runtime label is invocation metadata; C/HighFunction artifacts record actual observed output.\n").append(log);
        Files.writeString(output.resolve(profile.id() + "-validation.txt"), result);
        println("TLINK PROFILE VALIDATION PASS " + profile.id() + " " + args[2] + " " + args[3]);
    }

    private String collectProfileChanges() throws Exception {
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        int logStart = manager.getMessageLog().toString().length();
        StringBuilder finalLog = new StringBuilder();
        // The manager clears its log after notifying completion listeners.
        AutoAnalysisManagerListener listener = (completedManager, cancelled) -> {
            String messages = completedManager.getMessageLog().toString();
            if (!cancelled && messages.length() > logStart) {
                finalLog.append(messages.substring(logStart));
            }
        };
        manager.addListener(listener);
        try {
            analyzeChanges(currentProgram);
        }
        finally {
            manager.removeListener(listener);
        }
        return finalLog.toString();
    }

    private void analyzeProfileChanges(String profileId) throws Exception {
        String finalLog = collectProfileChanges();
        require(finalLog.contains("Applied " + profileId + " final facts"), "Production final stage must execute successfully before rerun assertions: " + finalLog);
    }

    @FunctionalInterface
    private interface Fixture {
        void install() throws Exception;
    }

    private void fixture(String name, Fixture fixture) throws Exception {
        require(AutoAnalysisManager.getAnalysisManager(currentProgram).scheduleWorker(new AnalysisWorker() {
            public String getWorkerName() {
                return name;
            }
            public boolean analysisWorkerCallback(Program program, Object ignored, TaskMonitor workerMonitor) throws Exception {
                fixture.install();
                return true;
            }
        }, null, false, monitor), "Install native fixture without queuing unrelated inference: " + name);
    }

    private void decodeFixture(Address start, Address end) {
        Address cursor = start;
        while (cursor.compareTo(end) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            if (instruction == null) {
                var command = new DisassembleCommand(cursor, new AddressSet(start, end), false);
                command.enableCodeAnalysis(false);
                require(command.applyTo(currentProgram, monitor), "Decode deliberately changed native fixture: " + command.getStatusMsg());
                instruction = currentProgram.getListing().getInstructionAt(cursor);
            }
            require(instruction != null && instruction.getMaxAddress().compareTo(end) <= 0, "Complete fixture instruction within its original extent");
            cursor = cursor.add(instruction.getLength());
        }
    }

    private String references(Address start, Address end) {
        StringBuilder snapshot = new StringBuilder();
        for (Address address : new AddressSet(start, end).getAddresses(true)) {
            var refs = currentProgram.getReferenceManager().getReferencesFrom(address);
            snapshot.append(address).append(' ').append(Arrays.stream(refs).map(r -> r.getToAddress() + "/" + r.getReferenceType() + "/" + r.getSource() + "/" + r.getOperandIndex()).sorted().toList()).append(';');
        }
        return snapshot.toString();
    }

    private String instructionState(Instruction instruction) throws Exception {
        return HexFormat.of().formatHex(instruction.getBytes()) + " " + instruction + " " + Arrays.stream(instruction.getPcode(true)).map(Object::toString).toList();
    }

    private String repeat51() throws Exception {
        MessageLog preparation = new MessageLog();
        require(new Tlink51Profile().match(currentProgram, monitor) != null, "Actual original FileBytes identity remains true after current-code/manual changes");
        require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, preparation), "Actual production early data phase must succeed before late qualification: " + preparation);
        return collectProfileChanges();
    }

    private void restore51() throws Exception {
        String log = repeat51();
        require(log.contains("Applied " + Tlink51Profile.ID + " final facts") && log.contains("Seven dependent conditional inline-return edits applied."), "Restored original must requalify through actual production, including seven joins: " + log);
    }

    private void checkPatchedFunction51(String name, long entryFile, long patchFile, int originalByte, int patchedByte, int purge) throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        var manager = currentProgram.getFunctionManager();
        Address entry = context.mapped(entryFile);
        Address patch = context.mapped(patchFile);
        Function function = manager.getFunctionAt(entry);
        require(function != null && function.getSymbol().getSource() == SourceType.ANALYSIS && !function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS), "Counterexample must target existing ANALYSIS facts, not a manual-function guard: " + name);
        require(Byte.toUnsignedInt(context.original().getOriginalByte(patchFile)) == originalByte && Byte.toUnsignedInt(memory.getByte(patch)) == originalByte, "Actual named original/current opcode for " + name);
        var instruction = listing.getInstructionAt(patch);
        byte[] loaded = instruction.getBytes();
        Address end = instruction.getMaxAddress();
        int previousPurge = function.getStackPurgeSize();
        String previousComment = function.getComment();
        fixture("Install " + name, () -> {
            listing.clearCodeUnits(patch, end, false);
            memory.setByte(patch, (byte) patchedByte);
            decodeFixture(patch, end);
            function.setStackPurgeSize(purge);
            function.setComment("Manual current-code facts for " + name);
            currentProgram.getReferenceManager().addMemoryReference(patch, context.mapped(0x4e0b), RefType.DATA, SourceType.USER_DEFINED, 0);
            currentProgram.getReferenceManager().addMemoryReference(end, context.mapped(0x4e0c), RefType.DATA, SourceType.USER_DEFINED, 1);
        });
        String beforeInstruction = instructionState(listing.getInstructionAt(patch));
        String beforeRefs = references(patch, end);
        long beforeId = function.getID();
        AddressSet beforeBody = new AddressSet(function.getBody());
        String beforeSignature = function.getPrototypeString(true, true);
        String beforeComment = function.getComment();
        result.append(name).append(" before: FILE").append(Long.toHexString(patchFile)).append(' ').append(beforeInstruction).append(";functionID=").append(beforeId).append(";body=").append(beforeBody).append(";purge=").append(purge).append(";refs=").append(beforeRefs).append('\n');
        String log = repeat51();
        require(log.contains("preserving current code") && log.contains("FILE " + Long.toHexString(patchFile)) && !log.contains("Applied " + Tlink51Profile.ID + " final facts"), "Visible current-code refusal without false final success: " + name + " " + log);
        var after = manager.getFunctionAt(entry);
        var afterInstruction = listing.getInstructionAt(patch);
        require(after != null && after.getID() == beforeId && beforeBody.equals(after.getBody()) && beforeSignature.equals(after.getPrototypeString(true, true)) && after.getStackPurgeSize() == purge && beforeComment.equals(after.getComment()), "Refusal must preserve current function identity/body/signature/purge/comment, not just patched bytes: " + name);
        require(afterInstruction != null && beforeInstruction.equals(instructionState(afterInstruction)) && beforeRefs.equals(references(patch, end)), "Refusal must preserve native instruction/effective pcode and all references over its full extent: " + name);
        result.append(name).append(" after refusal: ").append(instructionState(afterInstruction)).append(";functionID=").append(after.getID()).append(";body=").append(after.getBody()).append(";purge=").append(after.getStackPurgeSize()).append(";refs=").append(references(patch, end)).append(";original identity=true;no final success.\n");
        fixture("Restore " + name, () -> {
            listing.clearCodeUnits(patch, end, false);
            memory.setBytes(patch, loaded);
            decodeFixture(patch, end);
            function.setStackPurgeSize(previousPurge);
            function.setComment(previousComment);
        });
        restore51();
    }

    private void checkPreservedInlinePrerequisite51(long entryFile, boolean manualFlow) throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        Address entry = context.mapped(entryFile);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        String originalName = function.getName();
        SourceType originalNameSource = function.getSymbol().getSource();
        SourceType originalSignatureSource = function.getSignatureSource();
        var originalReturn = function.getReturnType();
        AddressSet originalBody = new AddressSet(function.getBody());
        int originalPurge = function.getStackPurgeSize();
        String originalComment = function.getComment();
        byte[] loaded = new byte[8];
        boolean ordinaryReturn = entryFile == 0xc6f0;
        if (ordinaryReturn) {
            require(memory.getBytes(entry, loaded) == loaded.length, "Retain actual eight-byte consumed-return helper before ordinary RET fixture");
        }
        String[] originalComments = new String[INLINE_TEXT_JOINS.length];
        for (int i = 0; i < INLINE_TEXT_JOINS.length; i++) {
            originalComments[i] = listing.getComment(CommentType.PLATE, context.mapped(0x1200 + INLINE_TEXT_JOINS[i][0]));
        }
        fixture("Install preserved inline prerequisite FILE" + Long.toHexString(entryFile), () -> {
            function.setName("manual_prerequisite_" + Long.toHexString(entryFile), SourceType.USER_DEFINED);
            function.setReturnType(UnsignedShortDataType.dataType, SourceType.USER_DEFINED);
            function.setStackPurgeSize(29);
            function.setComment("Manual prerequisite contract FILE" + Long.toHexString(entryFile));
            if (ordinaryReturn) {
                listing.clearCodeUnits(entry, entry.add(7), false);
                memory.setBytes(entry, new byte[] {(byte) 0xc3,(byte) 0x90,(byte) 0x90,(byte) 0x90,(byte) 0x90,(byte) 0x90,(byte) 0x90,(byte) 0x90});
                decodeFixture(entry, entry.add(7));
            }
            if (entryFile == 0xeff9) {
                function.setBody(context.range(0xeff9, 0xf02f));
            }
            for (int i = 0; i < INLINE_TEXT_JOINS.length; i++) {
                int[] join = INLINE_TEXT_JOINS[i];
                var call = listing.getInstructionAt(context.mapped(0x1200 + join[0]));
                call.clearFallThroughOverride();
                if (manualFlow && i == 0) {
                    call.setFallThrough(context.mapped(0xf059));
                }
                var reference = currentProgram.getReferenceManager().getReference(call.getAddress(), context.mapped(0x1200 + join[1]), 0);
                require(reference != null && reference.getReferenceType() == RefType.DATA && reference.getSource() == SourceType.ANALYSIS, "Remove only this fixture's prior profile-dependent DATA reference");
                currentProgram.getReferenceManager().delete(reference);
                listing.setComment(call.getAddress(), CommentType.PLATE, "Manual current caller " + Integer.toHexString(join[0]));
            }
        });
        long id = function.getID();
        String signature = function.getPrototypeString(true, true);
        AddressSet body = new AddressSet(function.getBody());
        String comment = function.getComment();
        Address[] flows = new Address[INLINE_TEXT_JOINS.length];
        boolean[] overridden = new boolean[INLINE_TEXT_JOINS.length];
        String[] refs = new String[INLINE_TEXT_JOINS.length];
        for (int i = 0; i < INLINE_TEXT_JOINS.length; i++) {
            var call = listing.getInstructionAt(context.mapped(0x1200 + INLINE_TEXT_JOINS[i][0]));
            flows[i] = call.getFallThrough();
            overridden[i] = call.isFallThroughOverridden();
            refs[i] = references(call.getAddress(), call.getAddress());
        }
        String log = repeat51();
        require(log.contains("Applied " + Tlink51Profile.ID + " final facts") && log.contains("Dependent inline-return edits skipped for preserved prerequisites.") && !log.contains("Seven dependent conditional inline-return edits applied."), "Independent facts may apply, but preserved prerequisites must visibly skip dependent joins: " + log);
        require(function.getID() == id && function.getSignatureSource() == SourceType.USER_DEFINED && signature.equals(function.getPrototypeString(true, true)) && body.equals(function.getBody()) && function.getStackPurgeSize() == 29 && function.getComment().startsWith(comment), "Preserve actual prerequisite identity/signature/body/purge and manual comment text FILE" + Long.toHexString(entryFile));
        if (ordinaryReturn) {
            require(listing.getInstructionAt(entry).getFlowType().isTerminal() && Arrays.stream(listing.getInstructionAt(entry).getPcode(true)).anyMatch(op -> op.getOpcode() == PcodeOp.RETURN), "Preserved consume helper actually has ordinary RET/RETURN behavior");
        }
        result.append("F3 preserved prerequisite FILE").append(Long.toHexString(entryFile)).append(";functionID=").append(id).append(";signature=").append(signature).append(";body=").append(body).append(";purge29;ordinary RET=").append(ordinaryReturn).append(";dependent flow/reference/comment edits skipped.\n");
        for (int i = 0; i < INLINE_TEXT_JOINS.length; i++) {
            int[] join = INLINE_TEXT_JOINS[i];
            var call = listing.getInstructionAt(context.mapped(0x1200 + join[0]));
            require(Objects.equals(flows[i], call.getFallThrough()) && overridden[i] == call.isFallThroughOverridden() && refs[i].equals(references(call.getAddress(), call.getAddress())), "Preserved prerequisite must not install or remap conditional fallthrough/DATA references at " + Integer.toHexString(join[0]));
            require(("Manual current caller " + Integer.toHexString(join[0])).equals(listing.getComment(CommentType.PLATE, call.getAddress())), "Preserved prerequisite must not append dependent caller contract comments");
            result.append("  CALL ").append(Integer.toHexString(join[0])).append(" unchanged fallthrough=").append(call.getFallThrough()).append(";overridden=").append(call.isFallThroughOverridden()).append(";refs=").append(refs[i]).append('\n');
        }
        fixture("Restore inline prerequisite FILE" + Long.toHexString(entryFile), () -> {
            if (ordinaryReturn) {
                listing.clearCodeUnits(entry, entry.add(7), false);
                memory.setBytes(entry, loaded);
                decodeFixture(entry, entry.add(7));
            }
            function.setName(originalName, originalNameSource);
            function.setReturnType(originalReturn, originalSignatureSource);
            function.setSignatureSource(originalSignatureSource);
            function.setBody(originalBody);
            function.setStackPurgeSize(originalPurge);
            function.setComment(originalComment);
            for (int i = 0; i < INLINE_TEXT_JOINS.length; i++) {
                var call = listing.getInstructionAt(context.mapped(0x1200 + INLINE_TEXT_JOINS[i][0]));
                call.clearFallThroughOverride();
                listing.setComment(call.getAddress(), CommentType.PLATE, originalComments[i]);
            }
        });
        restore51();
    }

    private boolean contains(Varnode[] storage, String name) {
        Register register = currentProgram.getRegister(name);
        return Arrays.stream(storage).anyMatch(v -> v.getAddress().equals(register.getAddress()) && v.getSize() == register.getMinimumByteSize());
    }

    private void checkWriterBody(Function writer, long file, Path output) throws Exception {
        byte[] actual = new byte[150];
        require(currentProgram.getMemory().getBytes(writer.getEntryPoint(), actual) == 150, "Complete loaded writer bytes");
        byte[] original = new byte[150];
        require(context.original().getOriginalBytes(file, original) == 150 && Arrays.equals(actual, original), "No native relocation/patch changes the qualified writer bytes");
        StringBuilder raw = new StringBuilder();
        int calls = 0;
        int esWrites = 0;
        int cxSubtracts = 0;
        boolean dxAddition = false;
        boolean carrySet = false;
        boolean carryClear = false;
        for (var instruction : currentProgram.getListing().getInstructions(writer.getBody(), true)) {
            raw.append(instruction.getAddress()).append(' ').append(HexFormat.of().formatHex(instruction.getBytes())).append(' ').append(instruction).append('\n');
            if (instruction.getFlowType().isCall()) {
                calls++;
            }
            for (PcodeOp op : instruction.getPcode()) {
                raw.append("  ").append(op).append('\n');
                if (outputIs(op, "ES")) {
                    esWrites++;
                }
                if (outputIs(op, "CX") && op.getOpcode() == PcodeOp.INT_SUB) {
                    cxSubtracts++;
                }
                if (outputIs(op, "DX") && op.getOpcode() == PcodeOp.INT_ADD && op.getInput(1).isConstant() && op.getInput(1).getOffset() == 0xf802) {
                    dxAddition = true;
                }
                if (outputIs(op, "CF") && op.getOpcode() == PcodeOp.COPY && op.getInput(0).isConstant()) {
                    carrySet |= op.getInput(0).getOffset() == 1;
                    carryClear |= op.getInput(0).getOffset() == 0;
                }
            }
        }
        require(calls == 0 && esWrites == 2 && cxSubtracts == 3 && dxAddition && carrySet && carryClear, "Actual raw writer p-code establishes no helper calls, two ES selections, threeCX subtractions, fullDX+F802 and CF1/0 paths");
        for (int offset : new int[] { 0, 1, 2 }) {
            require(currentProgram.getListing().getInstructionAt(context.mapped(file + offset)).getMnemonicString().equalsIgnoreCase("PUSH"), "Actual three saved registers at writer entry");
        }
        require(currentProgram.getListing().getInstructionAt(context.mapped(file + 149)).getMnemonicString().equalsIgnoreCase("RET"), "Actual near RET at final byte");
        Files.write(output.resolve("writer-loaded.bin"), actual);
        Files.writeString(output.resolve("writer-raw-pcode.txt"), raw);
        result.append("Writer:51 native instructions/150 unchanged bytes, CF1/0, fullDX+F802, threeCX subtractions, twoES assignments, noCALL. Dedicated output7 near model with explicit clobbers; no default-ES preservation.\n");
    }

    private boolean outputIs(PcodeOp op, String name) {
        var register = currentProgram.getRegister(name);
        return op.getOutput() != null && op.getOutput().getAddress().equals(register.getAddress()) && op.getOutput().getSize() == register.getMinimumByteSize();
    }

    private void check51() throws Exception {
        checkType(Tlink51Profile.TYPES, "SegmentInfo10Partial", 10, new int[] {0,2,6,8,9});
        checkType(Tlink51Profile.TYPES, "AssociatedEntry10Partial", 10, new int[] {0,2});
        checkType(Tlink51Profile.TYPES, "Descriptor20Partial", 20, new int[] {1,2,4,6,8,10,13,15,17,19});
        checkType(Tlink51Profile.TYPES, "Association12Partial", 12, new int[] {0,2,4,6,8,10});
        checkType(Tlink51Profile.TYPES, "NameBoundRecord15Partial", 15, new int[] {0,2,8,10,12,14});
        checkType(Tlink51Profile.TYPES, "VectorDescriptor8Partial", 8, new int[] {0,2,4,6});
        checkType(Tlink51Profile.TYPES, "FixupWorking8", 8, new int[] {0,1,2,4,6});
        checkType(Tlink51Profile.TYPES, "OutputHeader64Partial", 64, new int[] {0,2,3,4,6,0x1c,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x32,0x34,0x36});
        checkType(Tlink51Profile.TYPES, "OutputSegmentRecord8", 8, new int[] {0,2,4,6});
        checkType(Tlink51Profile.TYPES, "Nb02InitialWorking16", 16, new int[] {0,4});
        checkType(Tlink51Profile.TYPES, "Nb02TerminalWorking8", 8, new int[] {0,4});
        checkType(Tlink51Profile.TYPES, "MiddleWorkingRecordPartial", 0x30, new int[] {0,2,0x20,0x22,0x28});
        checkFunction(0x1200 + 0xd8e7, 0x1200 + 0xd976, 55);
        checkFunction(0x1200 + 0xd84a, 0x1200 + 0xd8e7, 59);
        checkFunction(0x1200 + 0xbcdd, 0x1200 + 0xbeaf, 170);
        checkFunction(0x1200 + 0xbee1, 0x1200 + 0xc02f, 124);
        checkFunction(0x1200 + 0xc02f, 0x1200 + 0xc062, 19);
        checkFunction(0x1200 + 0x86bd, 0x1200 + 0x87d8, 107);
        checkFunction(0x1200 + 0xab98, 0x1200 + 0xabb0, 13);
        checkFunction(0x1200 + 0x4c31, 0x1200 + 0x4c8b, 39);
        checkFunction(0x1200 + 0x6d01, 0x1200 + 0x6d19, 10);
        checkFunction(0x1200 + 0x9e96, 0x1200 + 0x9edf, 36);
        checkFunction(0x1200 + 0x9bd6, 0x1200 + 0x9c15, 30);
        checkNear(0x1200 + 0x3d6e, 0x4e0b);
        checkNear(0x1200 + 0x4302, 0x4e0b);
        checkNear(0x1200 + 0x432c, 0x4e0b);
        checkNear(0x1200 + 0xd8ce, 0x1200 + 0xd8e7);
        for (int call : new int[] { 0x8718,0x8784,0x87cf,0xbedd,0xc059,0x4c81 }) {
            checkNear(0x1200 + call, 0x1200 + 0x9e96);
        }
        checkBytes(0x1200 + 0x0726, "881ea901");
        checkBytes(0x1200 + 0x4c63, "12cd");
        checkBytes(0x1200 + 0x9ea6, "12d6");
        checkBytes(0x1200 + 0x9ec4, "12d6");
        // Owner-controlled R118/K2,R206,R162/R169/R181/R220 byte anchors, not synthetic records.
        checkInstruction(0x3c2b, "263b5d04");
        checkInstruction(0x7f43, "26897504");
        checkInstruction(0x7f4e, "26894506");
        checkInstruction(0xd927, "268f4502");
        checkInstruction(0xd92f, "26c6450e20");
        checkInstruction(0xd95a, "26f6450e10");
        checkInstruction(0xd961, "268f4502");
        checkInstruction(0xd965, "26804d0e20");
        checkInstruction(0xd96a, "2680650eef");
        checkInstruction(0xbcdd, "c7065f084e45");
        checkInstruction(0xbdca, "a38108");
        checkInstruction(0xbe11, "a38308");
        checkInstruction(0xbe14, "a38508");
        checkInstruction(0xbf04, "268b470d");
        checkInstruction(0xbf4a, "a3b108");
        checkInstruction(0xbf4d, "a3ad08");
        checkInstruction(0xbfa1, "d1ea");
        checkInstruction(0xbfa3, "d1d8");
        checkInstruction(0xbfa5, "e2fa");
        checkInstruction(0x8700, "b84e42");
        checkInstruction(0x8704, "b83032");
        checkInstruction(0x8724, "c704fb52");
        checkInstruction(0x879b, "b84e42");
        checkInstruction(0x879f, "b83032");
        checkInstruction(0x4c46, "268b440d");
        checkInstruction(0x4c4a, "268b5411");
        checkInstruction(0x4c4e, "26ff4411");
        checkInstruction(0x4c79, "8b0ea605");
        checkInstruction(0x4c7d, "8b36a805");
        checkFunction(0x1200 + 0xb49f, 0x1200 + 0xb4c5, 24);
        checkFunction(0x1200 + 0xb4f0, 0x1200 + 0xb4f8, 5);
        Function shared = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x1200 + 0xddf9));
        require(shared != null && shared.getBody().getNumAddresses() == 286 && shared.getStackPurgeSize() == Function.UNKNOWN_STACK_DEPTH_CHANGE && !shared.hasNoReturn(), "Shared consumed-frame body is code-only286 bytes, unknown cleanup, not noreturn");
        AddressSet expectedBody = new AddressSet();
        for (int[] interval : ERROR_INTERVALS) {
            expectedBody.add(context.range(0x1200 + interval[0], 0x1200 + interval[1]));
        }
        require(shared.getBody().equals(expectedBody), "All eight exact code intervals must form the shared body, not just the same byte count");
        require(shared.getComment().contains("CURRENT count") && shared.getComment().contains("S+4+n"), "Current-count reconstructed-return semantics remain qualified");
        for (int[] join : INLINE_TEXT_JOINS) {
            checkNear(0x1200 + join[0], 0x1200 + 0xb4f0);
            var call = currentProgram.getListing().getInstructionAt(context.mapped(0x1200 + join[0]));
            require(call.getFallThrough().equals(context.mapped(0x1200 + join[2])), "Native explicit inline-text resume");
            var range = context.range(0x1200 + join[1], 0x1200 + join[2]);
            require(!shared.getBody().intersects(range), "No function body across inline data");
            var data = currentProgram.getListing().getDefinedDataAt(range.getMinAddress());
            require(data != null && data.getLength() == join[2] - join[1], "Length prefix and inline text are DATA");
            require(!currentProgram.getListing().getInstructions(range, true).hasNext(), "No instruction in inline data");
            require(Byte.toUnsignedInt(context.original().getOriginalByte(0x1200 + join[1])) == data.getLength() - 1, "Real prefix determines conditional resume, not synthetic expected text");
        }
        require(!shared.getBody().contains(context.mapped(0x1200 + 0xdf70)), "Separate DF70 FAR entry excluded");
        checkInstruction(0xde0d, "5a");
        checkInstruction(0xde0e, "55");
        checkInstruction(0xde0f, "8bec");
        checkInstruction(0xdf5e, "8b56f8");
        checkInstruction(0xdf61, "8b4604");
        checkInstruction(0xdf64, "050600");
        checkInstruction(0xdf67, "03c5");
        checkInstruction(0xdf6c, "8be0");
        checkInstruction(0xdf6e, "52");
        checkInstruction(0xdf6f, "c3");
        checkNear(0x1200 + 0xabc1, 0x1200 + 0xddfe);
        checkNear(0x1200 + 0xabe6, 0x1200 + 0xddfe);
        checkNear(0x1200 + 0xdf54, 0x1200 + 0x9b20);
        int ea = 0;
        int ff = 0;
        for (int i = 0; i < 105; i++) {
            long cell = 0x11802 + 5L * i;
            int first = Byte.toUnsignedInt(context.original().getOriginalByte(cell));
            var range = context.range(cell, cell + 5);
            if (Arrays.binarySearch(FAR_CODE_SLOTS, 2 + 5 * i) >= 0) {
                Function slot = currentProgram.getFunctionManager().getFunctionAt(range.getMinAddress());
                var instruction = currentProgram.getListing().getInstructionAt(range.getMinAddress());
                require(first == 0xea && slot != null && slot.getBody().equals(range) && instruction != null && instruction.getLength() == 5 && instruction.getFlowType().isJump(), "Each of the six selected raw EA slots is one complete native five-byte function");
                require(!currentProgram.getListing().getDefinedData(range, true).hasNext(), "Selected final-code slot must not retain early raw DATA");
            }
            else {
                var data = currentProgram.getListing().getDefinedDataAt(range.getMinAddress());
                require(data != null && data.getLength() == 5 && data.getDataType().getName().equals("StoredFarSlot5"), "All99 remaining raw slots, EA and FF, retain the exact native DATA representation");
                require(!currentProgram.getListing().getInstructions(range, true).hasNext() && !currentProgram.getFunctionManager().getFunctionsOverlapping(range).hasNext(), "Unselected raw slot remains DATA, not native code/function");
            }
            if (first == 0xea) {
                ea++;
                require(currentProgram.getReferenceManager().getReference(context.mapped(cell + 1), context.mapped(0x122fc), 0) != null, "Original EA slot target joins common trap, not invented loaded service");
            }
            else {
                require(first == 0xff && currentProgram.getListing().getDefinedDataAt(context.mapped(cell)) != null, "FF-leading position remains DATA, not executable FAR stub");
                ff++;
            }
        }
        require(ea == 97 && ff == 8, "105 raw positions partition97 EA/8 FF");
        for (long file : new long[] { 0xef30, 0x1180c, 0x11816, 0x118bb, 0x118e3, 0x118ed, 0x119ce, 0x122fc, 0x11c69 }) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(file));
            String comment = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(file));
            require(function != null && function.getStackPurgeSize() == Function.UNKNOWN_STACK_DEPTH_CHANGE && comment != null && comment.contains("; cleanup unknown, not total return-frame delta.") && !comment.contains("2147483647 argument bytes"), "Canonical native UNKNOWN cleanup and truthful qualification FILE " + Long.toHexString(file));
        }
        for (long[] numeric : new long[][] { {0x4e0b,0}, {0xefdc,2}, {0xbbdb,4} }) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(numeric[0]));
            String comment = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(numeric[0]));
            require(function != null && function.getStackPurgeSize() == numeric[1] && comment != null && comment.contains("; cleanup " + numeric[1] + " argument bytes, not total return-frame delta."), "Unchanged actual numeric cleanup/qualification FILE " + Long.toHexString(numeric[0]));
        }
        result.append("Canonical cleanup metadata:9 actual contiguous consumers retain native UNKNOWN with explicit unknown comments; actual0/2/4-byte cleanup contracts/comments unchanged.\n");
        checkFunction(0x122fc, 0x1231a, 18);
        checkFunction(0x11c69, 0x11ce7, 58);
        var backedge = currentProgram.getListing().getInstructionAt(context.mapped(0x11800 + 0x4de));
        require(Arrays.asList(backedge.getFlows()).contains(context.mapped(0x11800 + 0x4c3)), "Real patch-writer backedge does not reload CX at04B9");
        for (long[] join : new long[][] { {0x1200+0x665c,0x1180c}, {0x1200+0x9cf4,0x118e3}, {0x1200+0x9d01,0x118ed}, {0x1200+0x9d71,0x118bb}, {0x1200+0x9da4,0x1180c} }) {
            require(currentProgram.getReferenceManager().getReference(context.mapped(join[0]), context.mapped(join[1]), 0) != null, "Actual singleton FAR relocation reference");
        }
        result.append("5.1: separate dynamic-domain types/current consumers; actual writer/copy callers; header/segment/NB02 producers and finite numeric helpers; seven CALL/data/resume joins;286 code/89data bytes;six selected code/99 raw DATA slots within97EA/8FF/native target joins; patch backedge/current-state and IRET/service/codealias uncertainty qualified.\n");
    }

    private void check401() throws Exception {
        checkType(Tlink401Profile.TYPES, "Descriptor20Partial", 20, new int[] {1,4,6});
        checkType(Tlink401Profile.TYPES, "AssociatedEntry10Partial", 10, new int[] {0,2});
        checkFunction(0x3556, 0x3622, 75);
        checkFunction(0x6e8f, 0x702a, 158);
        checkFunction(0x70fb, 0x7127, 22);
        checkFunction(0x716e, 0x7559, 353);
        checkNear(0x35a5, 0x3458);
        checkNear(0x3b0f, 0x3458);
        checkBytes(0x3546, "b2316631b6319831b231aa31b231b231");
        require(currentProgram.getListing().getDefinedDataAt(context.mapped(0x3546)).getLength() == 16, "4.01 dispatcher table is separate data");
        require(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x35a5)) == null || !currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x35a5)).contains("01A9"), "No5.1 disable-latch transport");
        result.append("4.01: native MZ/file0400 mapping, independent representative/control and actual nearCALL joins. No5.1-specific option/association/output/inline/service facts transported.\n");
    }

    private Function checkFunction(long first, long end, int count) {
        var function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(first));
        require(function != null && function.getBody().equals(context.range(first, end)), "Complete qualified function extent FILE " + Long.toHexString(first));
        int actual = 0;
        Address cursor = context.mapped(first);
        while (cursor.compareTo(context.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(context.mapped(end - 1)) <= 0, "Complete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            actual++;
        }
        require(actual == count, "Native instruction count FILE " + Long.toHexString(first) + ": " + actual + " vs " + count);
        result.append("FUNCTION FILE[").append(Long.toHexString(first)).append(',').append(Long.toHexString(end)).append(") native-instructions=").append(actual).append('\n');
        return function;
    }

    private void checkType(CategoryPath category, String name, int length, int[] fields) {
        var type = currentProgram.getDataTypeManager().getDataType(category, name);
        require(type instanceof Structure && type.getLength() == length, "Native structure " + name);
        for (int field : fields) {
            require(((Structure) type).getComponentAt(field).getOffset() == field, "Qualified field boundary in " + name + " at " + field);
        }
    }

    private void checkNear(long source, long target) {
        var instruction = currentProgram.getListing().getInstructionAt(context.mapped(source));
        require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(context.mapped(target)), "Actual native near CALL FILE " + Long.toHexString(source) + "→" + Long.toHexString(target));
    }

    private void checkBytes(long offset, String hex) throws Exception {
        byte[] expected = HexFormat.of().parseHex(hex);
        byte[] actual = new byte[expected.length];
        require(context.original().getOriginalBytes(offset, actual) == actual.length && Arrays.equals(actual, expected), "Named source bytes FILE " + Long.toHexString(offset));
    }

    private void checkInstruction(int ne1Offset, String hex) throws Exception {
        long file = 0x1200L + ne1Offset;
        checkBytes(file, hex);
        var instruction = currentProgram.getListing().getInstructionAt(context.mapped(file));
        require(instruction != null && HexFormat.of().formatHex(instruction.getBytes()).equals(hex), "Native instruction owns qualified field-consumer/store anchor NE1:" + Integer.toHexString(ne1Offset));
    }

    private void decompileWriter(Function writer, Path output) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Native decompiler opens Program");
            var decompiled = decompiler.decompileFunction(writer, 60, monitor);
            require(decompiled.decompileCompleted() && decompiled.getHighFunction() != null, "Actual writer decompilation completed: " + decompiled.getErrorMessage());
            var high = decompiled.getHighFunction();
            StringBuilder pcode = new StringBuilder();
            boolean output7 = false;
            int segmentOps = 0;
            var ops = high.getPcodeOps();
            while (ops.hasNext()) {
                var op = ops.next();
                pcode.append(op.getSeqnum()).append(' ').append(op).append('\n');
                output7 |= op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() == 2 && op.getInput(1).getSize() == 7;
                if (op.getOpcode() == PcodeOp.SEGMENTOP) {
                    segmentOps++;
                }
            }
            require(output7, "HighFunction retains full seven-byte analysis result at RETURN");
            var xml = new XmlEncode();
            high.encode(xml, writer.getID(), writer.getParentNamespace(), writer.getEntryPoint(), 150);
            Files.writeString(output.resolve("writer-high-prototype.xml"), xml.toString());
            Files.writeString(output.resolve("writer-high-pcode.txt"), pcode);
            Files.writeString(output.resolve("writer.c"), decompiled.getDecompiledFunction().getC());
            result.append("Native writer decompile completed; high seven-byte RETURN=true; SEGMENTOP count=").append(segmentOps).append("; error=").append(decompiled.getErrorMessage()).append('\n');
        }
        finally {
            decompiler.dispose();
        }
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
