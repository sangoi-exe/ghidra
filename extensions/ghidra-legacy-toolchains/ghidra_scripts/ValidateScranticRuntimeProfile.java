// Arguments: supplied original SCRANTIC.EXE, existing private output directory, direct|automatic.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.ScranticRuntimeProfile;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateScranticRuntimeProfile extends GhidraScript {
    private ToolchainProfile.Context context;
    private final StringBuilder result = new StringBuilder();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected original path, private output directory and direct|automatic (no silent fallback)");
        ScranticRuntimeProfile profile = new ScranticRuntimeProfile();
        context = profile.match(currentProgram, monitor);
        require(context != null, "Native NE import must retain exact qualified original FileBytes");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Imported original must literally equal named source input, not relocated memory");
        MessageLog log = new MessageLog();
        boolean automatic = args[2].equals("automatic");
        if (automatic) {
            require(hasLabel(0xde2, "scrantic_cwm31_lseek_correspondence"), "Automatic mode requires production analyzer activation before this script; no apply fallback");
            require(new ToolchainProfileAnalyzer().canAnalyze(currentProgram), "Production registry must qualify this original");
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }
        result.append(automatic ? "AUTOMATIC production activation asserted before script.\n" : "EXPLICIT DIRECT application only; registry activation unproved.\n");
        result.append("Ghidra ").append(getGhidraVersion()).append("; ").append(currentProgram.getExecutableFormat()).append("; ").append(currentProgram.getLanguageID()).append("; literal original equality ").append(original.length).append(" bytes\n");

        originalBytes(0xde2, "45558bec8b5e06d1e381a7f82afffdb4428a460c8b5e068b4e0a8b5608cd217202eb0550e8dffe995d4dcb");
        originalBytes(0x2eb8, "45558bec83ec0656578b46060b4608750633d233c0eb2ba127008946fe8b460aa327008b56088b4606569affff00005e8c46fc897efa8b46fea327008b56fc8b46fa5f5e8be55d4dcb");
        originalBytes(0x2f76, "45558bec83ec0256578b46060b4608741ca127008946fe8b460aa32700c47e06569affff00005e8b46fea327005f5e8be55d4dcb");
        originalBytes(0x2a9c, "45558bec33c050ff76069affff00005d4dcb");
        originalBytes(0x2aae, "45558bec8b46068b56080bc07508520ee8dbff59eb1a0bd2750b50900ee82a005933c0eb0b5052b80200509affff00005d4dcb");
        originalBytes(0x2ae1, "45558becb84000508b4608f76e06509affff00005d4dcb");
        originalBytes(0x2af8, "45558becff76069affff00005d4dcb");
        originalBytes(0x2b07, "0045558bec");
        completeFunction(0xde2, 0xe0d, 0, 20);
        completeFunction(0x2eb8, 0x2f01, 0, 33);
        completeFunction(0x2f76, 0x2faa, 0, 25);
        int unknown = Function.UNKNOWN_STACK_DEPTH_CHANGE;
        completeFunction(0x2a9c, 0x2aae, unknown, 10);
        completeFunction(0x2aae, 0x2ae1, unknown, 29);
        completeFunction(0x2ae1, 0x2af8, unknown, 12);
        completeFunction(0x2af8, 0x2b07, unknown, 8);
        nearCall(0xe06, 0xce8);
        nearCall(0x2abe, 0x2a9c);
        nearCall(0x2acb, 0x2af8);
        internalBinding(0x2ee3, 0x179e5, 0x07e5);
        internalBinding(0x2f98, 0x17b62, 0x0962);
        importedBinding(0x2aa7, 5);
        importedBinding(0x2ada, 6);
        importedBinding(0x2af1, 5);
        importedBinding(0x2b00, 7);
        for (long field : new long[] { 0x2ed0, 0x2ed9, 0x2ef2, 0x2f88, 0x2f91, 0x2fa1 }) {
            originalBytes(field, "2700");
            require(Short.toUnsignedInt(currentProgram.getMemory().getShort(context.mapped(field))) == 0x27, "FHEAP global displacement must remain original0027");
        }
        require(hasLabel(0xded, "scrantic_lseek_dgroup_displacement_binding") && hasLabel(0x17e27, "scrantic_fheap_dgroup_0027_binding"), "Member displacement bindings must have native analysis labels");
        require(comment(0x2af8).contains("NEGATIVE") && comment(0x2af8).contains("not genuine HEAP _free20"), "Original15 must retain negative vendor FREE20 qualification");
        require(comment(0x2aae).contains("raw-caller-qualified") && comment(0x2aae).contains("transitive HEAP equivalence is false"), "Complete member grouping must not invent executable ingress or transitive supplier equivalence");
        require(comment(0x2a9c).contains("cleanup unknown") && !comment(0x2a9c).contains(unknown + " argument bytes"), "Native UNKNOWN must be rendered honestly, not as a negative byte count");
        require(comment(0xde2).contains("not a historical Johnny name or modern lseek ABI") && comment(0x179e5).contains("label only"), "Names and unproved subordinate extents must remain qualified");
        result.append("Seven original complete extents, three real near wires, two relocated internal FAR bindings and four imported-field qualifications asserted.\n");

        String format = currentProgram.getExecutableFormat();
        try {
            currentProgram.setExecutableFormat("not the qualified NE format");
            require(profile.match(currentProgram, monitor) == null, "Wrong executable format must not qualify");
        }
        finally {
            currentProgram.setExecutableFormat(format);
        }
        require(profile.match(currentProgram, monitor) != null, "Restored original format must qualify");
        // Original FileBytes must win over the mutable current executable path.
        String path = currentProgram.getExecutablePath();
        try {
            currentProgram.setExecutablePath("/not/an/original/SCRANTIC.EXE");
            require(profile.match(currentProgram, monitor) != null, "Qualification must not depend on the current executable path");
        }
        finally {
            currentProgram.setExecutablePath(path);
        }
        result.append("Format rejection and original-FileBytes rather than executable-path qualification asserted.\n");

        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        int functions = currentProgram.getFunctionManager().getFunctionCount();
        String[] comments = comments();
        apply(profile, automatic, log);
        require(symbols == currentProgram.getSymbolTable().getNumSymbols() && functions == currentProgram.getFunctionManager().getFunctionCount(), "Repeated analysis must not duplicate symbols or functions");
        require(Arrays.equals(comments, comments()), "Repeated analysis must not duplicate any profile comment");

        Function guarded = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x2eb8));
        guarded.setName("user_owned_scrantic_member", SourceType.USER_DEFINED);
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        guarded.setStackPurgeSize(6);
        AddressSet body = new AddressSet(guarded.getBody());
        String signature = guarded.getPrototypeString(true, true);
        apply(profile, automatic, log);
        require(body.equals(guarded.getBody()) && signature.equals(guarded.getPrototypeString(true, true)) && guarded.getSignatureSource() == SourceType.USER_DEFINED && guarded.getStackPurgeSize() == 6, "Actual higher-priority user function/signature/body/cleanup must be preserved");
        result.append("Repeat has no duplicate symbols/functions/comments; actual user-owned function/signature/body/cleanup preserved. Disposable Program intentionally retains user edits.\n");
        result.append("Limits: no execution, modern ABI, import semantics/cleanup or whole allocator/vendor equivalence; native external thunks are analysis indirection, not actual imported implementations/runtime selectors.\n").append(log);
        Files.writeString(Path.of(args[1]).resolve("scrantic-runtime-profile-validation.txt"), result);
        println("SCRANTIC RUNTIME PROFILE VALIDATION PASS (" + args[2] + "): " + args[1]);
    }

    private void analyzeProfileChanges(String profileId) throws Exception {
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
        require(finalLog.toString().contains("Applied " + profileId + " final facts"), "Production final stage must execute successfully before rerun assertions: " + finalLog);
    }

    private void apply(ScranticRuntimeProfile profile, boolean automatic, MessageLog log) throws Exception {
        if (automatic) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analyzer rerun failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }
    }

    private void completeFunction(long start, long end, int purge, int count) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(start));
        require(function != null && function.getBody().equals(context.range(start, end)), "Incorrect complete original extent at FILE " + Long.toHexString(start));
        require(function.getStackPurgeSize() == purge, "Incorrect known/UNKNOWN cleanup at " + function.getEntryPoint());
        require(function.getSymbol().getSource() == SourceType.ANALYSIS, "Member qualification must be an analysis symbol, not an imported/historical name");
        Address cursor = context.mapped(start);
        int actual = 0;
        while (cursor.compareTo(context.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(context.mapped(end - 1)) <= 0, "Incomplete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            actual++;
        }
        require(actual == count, "Instruction count mismatch at " + function.getEntryPoint() + ": " + actual + " versus " + count);
        result.append("FUNCTION FILE [").append(Long.toHexString(start)).append(',').append(Long.toHexString(end)).append(") native ").append(function.getEntryPoint()).append(" instructions=").append(actual).append(" purge=").append(purge == Function.UNKNOWN_STACK_DEPTH_CHANGE ? "UNKNOWN" : purge).append('\n');
    }

    private void nearCall(long source, long target) {
        var instruction = currentProgram.getListing().getInstructionAt(context.mapped(source));
        require(instruction != null && instruction.getLength() == 3 && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(context.mapped(target)), "Actual near CALL must reach qualified original target at FILE " + Long.toHexString(source));
    }

    private void internalBinding(long source, long target, int offset) throws Exception {
        originalBytes(source, "ffff0000");
        Address field = context.mapped(source);
        var records = currentProgram.getRelocationTable().getRelocations(field);
        require(records.size() == 1, "Expected singleton native internal FAR relocation at " + field);
        Relocation relocation = records.get(0);
        long[] values = relocation.getValues();
        require(relocation.getStatus() == Relocation.Status.APPLIED && relocation.getType() == 3 && relocation.getLength() == 4 && values.length == 5 && values[1] == 0 && (values[3] & 0xffff) == 13 && (values[4] & 0xffff) == offset, "Original internal binding metadata must survive native relocation");
        int loadedOffset = Short.toUnsignedInt(currentProgram.getMemory().getShort(field));
        int selector = Short.toUnsignedInt(currentProgram.getMemory().getShort(field.add(2)));
        Address loaded = ((SegmentedAddressSpace) field.getAddressSpace()).getAddress(selector, loadedOffset);
        require(loaded.equals(context.mapped(target)), "Loaded FAR pair must equal unique original-file mapping");
        var reference = currentProgram.getReferenceManager().getReference(field, loaded, 0);
        require(reference != null && reference.getReferenceType() == RefType.DATA && reference.getSource() == SourceType.ANALYSIS, "Qualified operand must have a native analysis DATA binding reference");
        var instruction = currentProgram.getListing().getInstructionAt(field.subtract(1));
        require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(loaded), "Actual FAR CALL must resolve through native relocated binding");
        result.append("INTERNAL FIELD FILE ").append(Long.toHexString(source)).append(" native ").append(field).append(" -> NE13:").append(Integer.toHexString(offset)).append(" native ").append(loaded).append('\n');
    }

    private void importedBinding(long source, int ordinal) throws Exception {
        originalBytes(source, "ffff0000");
        Address field = context.mapped(source);
        require(comment(source).contains("module index3 KERNEL ordinal" + ordinal) && comment(source).contains("NOT a callee address") && comment(source).contains("does not fabricate"), "Import ordinal and loader limitations must remain explicit at actual field");
        // Actual native loader observations establish these applied external-thunk bindings.
        // A future missing binding must fail, not fabricate a call to raw FFFF:0000.
        var records = currentProgram.getRelocationTable().getRelocations(field);
        require(records.size() == 1, "Expected retained singleton native imported relocation metadata at " + field);
        for (Relocation relocation : records) {
            long[] values = relocation.getValues();
            require(relocation.getStatus() == Relocation.Status.APPLIED && relocation.getType() == 3 && relocation.getLength() == 4 && values.length == 5 && values[1] == 1 && values[3] == 3 && values[4] == ordinal, "Native imported binding must be applied and retain original module/ordinal metadata");
            int offset = Short.toUnsignedInt(currentProgram.getMemory().getShort(field));
            int selector = Short.toUnsignedInt(currentProgram.getMemory().getShort(field.add(2)));
            result.append("IMPORT FIELD FILE ").append(Long.toHexString(source)).append(" KERNEL ordinal").append(ordinal).append(" native status=").append(relocation.getStatus()).append(" loaded pair=").append(Integer.toHexString(selector)).append(':').append(Integer.toHexString(offset));
            require(selector != 0 || offset != 0xffff, "Applied import binding must not retain the raw source-chain placeholder");
            Address target = ((SegmentedAddressSpace) field.getAddressSpace()).getAddress(selector, offset);
            var instruction = currentProgram.getListing().getInstructionAt(field.subtract(1));
            require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(target), "Applied imported FAR CALL must reach the native loaded target");
            Function thunk = currentProgram.getFunctionManager().getFunctionAt(target);
            require(thunk != null && thunk.isThunk() && thunk.getThunkedFunction(true).isExternal(), "Applied import must resolve to a native external thunk, not an invented internal provider");
            result.append(" external thunk=").append(thunk.getThunkedFunction(true).getName(true));
            result.append("; no imported ABI/effects inferred\n");
        }
    }

    private String[] comments() {
        return Arrays.stream(new long[] { 0xde2, 0xded, 0xe06, 0xce8, 0x2eb8, 0x2f76, 0x2ee3, 0x2f98, 0x179e5, 0x17b62, 0x17e27, 0x2a9c, 0x2aae, 0x2ae1, 0x2af8, 0x2abe, 0x2acb, 0x2aa7, 0x2ada, 0x2af1, 0x2b00 }).mapToObj(this::comment).toArray(String[]::new);
    }

    private String comment(long file) {
        String value = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(file));
        require(value != null, "Missing qualification at FILE " + Long.toHexString(file));
        return value;
    }

    private boolean hasLabel(long file, String name) {
        var symbol = currentProgram.getSymbolTable().getSymbol(name, context.mapped(file), currentProgram.getGlobalNamespace());
        return symbol != null && symbol.getSource() == SourceType.ANALYSIS;
    }

    private void originalBytes(long file, String hex) throws Exception {
        byte[] expected = HexFormat.of().parseHex(hex);
        byte[] actual = new byte[expected.length];
        require(context.original().getOriginalBytes(file, actual) == actual.length && Arrays.equals(actual, expected), "Contradictory original bytes at FILE " + Long.toHexString(file));
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
