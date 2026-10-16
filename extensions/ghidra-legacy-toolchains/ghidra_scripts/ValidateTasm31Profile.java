// Native MZ exact-image integration check. Arguments: original TASM, private output directory, direct|automatic.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.Tasm31Profile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateTasm31Profile extends GhidraScript {
    private ToolchainProfile.Context context;
    private Tasm31Profile profile;
    private boolean automatic;
    private final StringBuilder result = new StringBuilder();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected original path, private output directory, explicit direct|automatic mode");
        automatic = args[2].equals("automatic");
        profile = new Tasm31Profile();
        context = profile.match(currentProgram, monitor);
        require(context != null, "Native MZ import must retain exact original TASM3.1 FileBytes identity");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Imported original FileBytes must be literally equal to named source, not relocated-memory equality");
        require(original.length == 129266 && currentProgram.getExecutableFormat().equals("Old-style DOS Executable (MZ)"), "Wrong native loader/image");
        require(currentProgram.getLanguageID().toString().equals("x86:LE:16:Real Mode"), "Expected native real-mode x86 language");
        result.append("Ghidra ").append(getGhidraVersion()).append("; ").append(currentProgram.getExecutableFormat()).append("; ").append(currentProgram.getLanguageID()).append('\n');
        MessageLog log = new MessageLog();
        if (automatic) {
            require(currentProgram.getSymbolTable().getSymbol("tasm31_call_dispatch_slot", context.mapped(0x1aaca), currentProgram.getGlobalNamespace()) != null, "Automatic mode requires initial production analyzer activation; no direct fallback is permitted");
            result.append("Initial production analyzer activation observed; no direct fallback.\n");
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
            result.append("EXPLICIT DIRECT APPLICATION: canonical profile invoked by this script; automatic registry activation is NOT proved.\n");
        }
        checkFunction(0x744d, 0x748d, 22);
        checkFunction(0x9490, 0x9501, 46);
        checkFunction(0x9461, 0x9490, 17);
        checkFunction(0x48f6, 0x4913, 11);
        checkFunction(0x4914, 0x492f, 8);
        checkFunction(0x4930, 0x494f, 9);
        checkFunction(0x22dc, 0x2302, 16);
        checkFunction(0xfe06, 0xfe45, 27);
        checkFunction(0xfe87, 0xfeba, 16);
        checkFunction(0x1084b, 0x10858, 4);
        checkFunction(0x167d2, 0x1685a, 45);
        checkFunction(0x13688, 0x1369b, 5);
        checkFunction(0x136dd, 0x136ee, 5);
        checkFunction(0x136ee, 0x13718, 10);
        checkFunction(0x1476f, 0x1479d, 16);
        checkFunction(0x1479d, 0x147cf, 15);
        for (long[] span : new long[][] { { 0x4db3, 0x4e1e }, { 0x4e1e, 0x4e94 }, { 0x4e94, 0x4eb2 }, { 0x4ef5, 0x4f15 }, { 0x4f15, 0x4f93 }, { 0x4f93, 0x4ff2 }, { 0x4ff2, 0x5022 }, { 0x5389, 0x53df }, { 0x5275, 0x52c6 }, { 0x13cb2, 0x13d65 }, { 0x14bc7, 0x14be5 } }) {
            checkFunction(span[0], span[1], -1);
        }
        checkAllocationPartition();
        checkBytes(0x1b310, "0443414c4c");
        checkBytes(0x1aaca, "05cf");
        checkBytes(0x1a20c, "080901");
        checkBytes(0x1a21e, "feff");
        checkBytes(0x19fc4, "0000000000000000000001000202");
        checkBytes(0x17fd9, "6fd917");
        checkBytes(0x4e65, "b090");
        checkBytes(0x4e4a, "50e8b8af5875");
        checkArray(0x1aa34, 554, 1108);
        checkArray(0x17faf, 78, 78);
        checkArray(0x19fc4, 14, 14);
        require(currentProgram.getListing().getDefinedDataAt(context.mapped(0x1f360)).getLength() == 40, "Initial replay context view must be40 bytes, excluding callback7078");
        require(currentProgram.getListing().getDefinedDataAt(context.mapped(0x1f4c6)).getLength() == 48, "Initial temporary snapshot storage must include callback7078 in48 bytes");
        checkReference(0x1aaca, 0xd705);
        checkReference(0x17fda, 0x18129);
        for (long[] pair : new long[][] { { 0x4dec, 0x167d2 }, { 0x4e05, 0x167d2 }, { 0x4ee4, 0x167d2 }, { 0xfe96, 0x1084b }, { 0xfeb1, 0x1084b }, { 0x11ce0, 0x175ef } }) {
            checkMzReference(pair[0], pair[1]);
        }
        checkStructure("Expression40Partial", 40, new int[] { 0, 1, 4, 5, 6, 0xa, 0x18, 0x1a, 0x1c, 0x24, 0x25, 0x26 }, new int[] { 1, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 2 });
        checkStructure("CompactReplayRecord16Partial", 16, new int[] { 0, 2, 4, 6, 8, 0xa, 0xc, 0xe }, new int[] { 2, 2, 2, 2, 2, 2, 2, 2 });
        checkStructure("FullReplayRecord46Partial", 0x2e, new int[] { 0, 2, 4, 6 }, new int[] { 2, 2, 2, 40 });
        checkStructure("ExtendedReplayHeader50Partial", 0x32, new int[] { 0, 0x2e, 0x30 }, new int[] { 46, 2, 2 });
        checkStructure("CallbackSnapshot48Partial", 48, new int[] { 0, 0x28, 0x2a, 0x2c, 0x2e }, new int[] { 40, 2, 2, 2, 2 });
        checkStructure("InternalQueuePayload9", 9, new int[] { 0, 1, 3, 5, 7 }, new int[] { 1, 2, 2, 2, 2 });
        checkStructure("ClassTaggedRecord32Partial", 32, new int[] { 0, 2, 4, 5, 6, 8, 0xa, 0x14, 0x1c, 0x1e }, new int[] { 2, 2, 1, 1, 2, 2, 2, 1, 2, 2 });
        require(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x2248)).contains("AX0 while ES remains selected"), "Lookup result must not acquire an unconditional pointer-return contract");
        require(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x4e1e)).contains("THEN-CURRENT AX"), "Fill must retain current-value/diagnostic qualification");
        // Prefixes and inline literal data must not gain profile-authored complete-function identities.
        for (long offset : new long[] { 0xfba9, 0xfd0d, 0xd705, 0x17faf, 0x18129, 0x4913 }) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(offset));
            require(function == null || !function.getName().startsWith("tasm31_"), "Unproved prefix/inline literal must not become a profile function at FILE " + Long.toHexString(offset));
        }
        int types = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        String before = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x4e1e));
        rerun(log);
        require(types == currentProgram.getDataTypeManager().getDataTypeCount(true), "Repeated profile application duplicates types");
        require(symbols == currentProgram.getSymbolTable().getNumSymbols(), "Repeated profile application duplicates symbols");
        require(before.equals(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x4e1e))), "Repeated profile application duplicates selected comments");
        result.append("Repeated ").append(automatic ? "production analyzer" : "explicit direct profile").append(" application: stable native types, labels, comments.\n");
        Function guarded = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x9490));
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        guarded.setName("user_owned_tasm_predicate", SourceType.USER_DEFINED);
        String signature = guarded.getPrototypeString(true, true);
        AddressSet body = new AddressSet(guarded.getBody());
        rerun(log);
        require(signature.equals(guarded.getPrototypeString(true, true)) && body.equals(guarded.getBody()) && guarded.getSignatureSource() == SourceType.USER_DEFINED, "Profile must preserve actual user-owned function/signature");
        result.append("Actual predicate USER_DEFINED signature/name/body preserved on rerun; disposable Program intentionally retains user signature.\n");
        result.append("Original FileBytes literally equal named source: ").append(original.length).append(" bytes; no original executed.\n").append(log).append('\n');
        Files.writeString(Path.of(args[1]).resolve("tasm31-profile-validation.txt"), result);
        println("TASM31 PROFILE VALIDATION PASS (" + args[2] + "): exact FileBytes, native MZ mapping/relocations/references, selected complete functions, partial layouts, tables, current-value qualifications, repeated application and user-source preservation.");
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

    private void rerun(MessageLog log) throws Exception {
        if (automatic) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analyzer rerun failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }
    }

    private void checkFunction(long start, long end, int count) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(start));
        require(function != null && function.getBody().equals(context.range(start, end)), "Wrong complete native function extent at FILE " + Long.toHexString(start));
        require(function.getStackPurgeSize() == 0, "Unexpected argument cleanup at " + function.getEntryPoint());
        var cursor = context.mapped(start);
        int actual = 0;
        while (cursor.compareTo(context.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(context.mapped(end - 1)) <= 0, "Incomplete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            actual++;
        }
        require(count < 0 || actual == count, "Instruction count disagrees with qualified original body at FILE " + Long.toHexString(start) + ": " + actual + " versus " + count);
        result.append("FUNCTION FILE [").append(Long.toHexString(start)).append(',').append(Long.toHexString(end)).append(") native ").append(function.getEntryPoint()).append(" instructions=").append(actual).append('\n');
    }

    private void checkAllocationPartition() throws Exception {
        AddressSet allocationBody = context.range(0x50cc, 0x50e2);
        allocationBody.add(context.range(0x50f2, 0x511a));
        Function allocation = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x50cc));
        require(allocation != null && allocation.getBody().equals(allocationBody) && allocation.getStackPurgeSize() == 0, "Allocation function must exclude the independently called shared clear entry");
        checkFunction(0x50e2, 0x50f2, 6);
        Function clear = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x50e2));
        require(clear != allocation && !allocation.getBody().intersects(clear.getBody()), "The two real entries must have disjoint native ownership");
        int allocationInstructions = 0;
        for (var part : allocationBody) {
            var cursor = part.getMinAddress();
            while (cursor.compareTo(part.getMaxAddress()) <= 0) {
                var instruction = currentProgram.getListing().getInstructionAt(cursor);
                require(instruction != null && instruction.getMaxAddress().compareTo(part.getMaxAddress()) <= 0, "Complete allocation code partition at " + cursor);
                cursor = cursor.add(instruction.getLength());
                allocationInstructions++;
            }
        }
        require(allocationInstructions == 19 && allocationBody.getNumAddresses() == 62 && clear.getBody().getNumAddresses() == 16, "Original78-byte selection partitions into62 allocation bytes/19 instructions and16 shared-clear bytes/6 instructions");
        checkBytes(0x5937, "e8a8f7");
        checkBytes(0x50cc, "833e1c7400");
        checkBytes(0x50d7, "b80300");
        checkBytes(0x50e2, "33c08bf8b91400f3ab26c606100001c3");
        DisassembleCommand callSite = new DisassembleCommand(context.mapped(0x5937), context.range(0x5937, 0x593a), false);
        callSite.enableCodeAnalysis(false);
        require(callSite.applyTo(currentProgram, monitor), "Native original shared-entry CALL disassembly");
        var call = currentProgram.getListing().getInstructionAt(context.mapped(0x5937));
        require(call != null && call.getLength() == 3 && call.getFlowType().isCall() && Arrays.asList(call.getFlows()).contains(clear.getEntryPoint()), "Actual independent near CALL must target the shared clear function");
        var fallthrough = currentProgram.getListing().getInstructionAt(context.mapped(0x50de));
        require(fallthrough != null && context.mapped(0x50e2).equals(fallthrough.getFallThrough()), "Allocation keeps its genuine fallthrough into the shared clear entry");
        var backedge = currentProgram.getListing().getInstructionAt(context.mapped(0x5118));
        require(backedge != null && Arrays.asList(backedge.getFlows()).contains(context.mapped(0x50d3)), "Allocation final backedge remains native48d3");
        result.append("FUNCTION allocation FILE[50cc,50e2)+[50f2,511a):62 bytes/19 instructions, cleanup0; separate shared clear FILE[50e2,50f2):16 bytes/6 instructions, cleanup0; original CALL5937, fallthrough50de and backedge5118 checked. THREE paragraphs remain distinct from40-byte clear.\n");
    }

    private void checkBytes(long offset, String hex) throws Exception {
        byte[] expected = HexFormat.of().parseHex(hex);
        byte[] actual = new byte[expected.length];
        require(context.original().getOriginalBytes(offset, actual) == actual.length && Arrays.equals(expected, actual), "Contradictory original bytes at FILE " + Long.toHexString(offset));
    }

    private void checkArray(long offset, int count, int length) {
        var data = currentProgram.getListing().getDefinedDataAt(context.mapped(offset));
        require(data != null && data.getDataType() instanceof Array && ((Array) data.getDataType()).getNumElements() == count && data.getLength() == length, "Wrong native table data at FILE " + Long.toHexString(offset));
        require(!currentProgram.getListing().getInstructions(context.range(offset, offset + length), true).hasNext(), "Native table data misidentified as instructions");
        result.append("DATA FILE ").append(Long.toHexString(offset)).append(" elements=").append(count).append(" bytes=").append(length).append('\n');
    }

    private void checkReference(long source, long target) {
        var reference = currentProgram.getReferenceManager().getReference(context.mapped(source), context.mapped(target), 0);
        require(reference != null && reference.getReferenceType() == RefType.DATA, "Missing qualified DATA reference at FILE " + Long.toHexString(source));
        result.append("REFERENCE FILE ").append(Long.toHexString(source)).append(" -> ").append(Long.toHexString(target)).append(" native ").append(context.mapped(source)).append(" -> ").append(context.mapped(target)).append('\n');
    }

    private void checkMzReference(long source, long target) {
        checkReference(source, target);
        var field = context.mapped(source + 2);
        require(currentProgram.getRelocationTable().getRelocations(field).stream().anyMatch(r -> r.getStatus() == Relocation.Status.APPLIED && r.getType() == 0 && r.getValues() != null && r.getValues().length == 3), "Missing actual native MZ relocation at " + field);
        var instruction = currentProgram.getListing().getInstructionAt(context.mapped(source - 1));
        // The qualified setup/later-control caller may not have been disassembled by the import's bounded automatic pass.
        if (source != 0x4ee4 && source != 0x11ce0) {
            require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(context.mapped(target)), "Actual native FAR CALL must resolve to file-mapped target at FILE " + Long.toHexString(source - 1));
        }
    }

    private void checkStructure(String name, int length, int[] offsets, int[] sizes) {
        var type = currentProgram.getDataTypeManager().getDataType(Tasm31Profile.TYPES, name);
        require(type instanceof Structure && type.getLength() == length, "Wrong partial native type " + name);
        Structure structure = (Structure) type;
        for (int i = 0; i < offsets.length; i++) {
            var field = structure.getComponentAt(offsets[i]);
            require(field != null && field.getOffset() == offsets[i] && field.getLength() == sizes[i], "Wrong field in " + name + " at " + offsets[i]);
        }
        result.append("TYPE ").append(type.getPathName()).append(" length=").append(length).append(" fields=").append(offsets.length).append('\n');
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
