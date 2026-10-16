// Native exact-image assertions. Arguments: named decoded original, private output directory, direct|automatic.
//@category LegacyToolchains

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.SimTowerRuntimeProfile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateSimTowerRuntimeProfile extends GhidraScript {
    private final SimTowerRuntimeProfile profile = new SimTowerRuntimeProfile();
    private final MessageLog log = new MessageLog();
    private final StringBuilder result = new StringBuilder();
    private ToolchainProfile.Context context;
    private boolean automatic;
    private int functions;
    private int dataReferences;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected named original, private output directory, direct|automatic");
        automatic = args[2].equals("automatic");
        Path output = Path.of(args[1]);
        context = profile.match(currentProgram, monitor);
        require(context != null, "Native original FileBytes must qualify the exact supplied SIMTOWER image");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Actual original FileBytes must literally equal the named source; not relocated memory or a filename");
        require(original.length == 6566400, "Documented original size");
        result.append("Ghidra ").append(getGhidraVersion()).append("; mode ").append(args[2]).append("; language ").append(currentProgram.getLanguageID()).append('\n');
        result.append("Named original literally equals all retained original FileBytes: ").append(original.length).append(" bytes.\n");
        if (automatic) {
            // Deliberately no direct apply fallback: this mode decides real registry/initial-analysis integration.
            label(0x2200, "simtower_c0wl45_startup_correspondence");
            label(0x60266, "simtower_xxv_raw_table42");
            require(new ToolchainProfileAnalyzer().canAnalyze(currentProgram), "Production analyzer must recognize this exact image in automatic mode");
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }

        mapping(1, 0x2200, 0x17a);
        mapping(1, 0x41f2, 1241);
        mapping(1, 0x5024, 146);
        mapping(1, 0x606a, 199);
        mapping(79, 0x60200, 849);
        mapping(82, 0x65030, 70);
        mapping(82, 0x657ec, 296);
        mapping(82, 0x65b5c, 103);
        mapping(82, 0x66036, 14);

        // SF02: complete startup code extent is correspondence coverage, not one fabricated function.
        function(0x22c9, 0x22db, 0);
        function(0x22db, 0x22dc, 0);
        function(0x22dc, 0x22dd, 0);
        function(0x22f2, 0x22f5, 0);
        function(0x22f5, 0x2339, 0);
        function(0x2339, 0x237a, 0);
        structure("StartupData70Partial", 70, new int[] {2,4,6,8,10,12,14,16,18,25,27}, new int[] {2,2,2,2,2,2,2,2,2,2,43});
        data(0x65030, 70);
        int[][] startupWords = { {0x24,0x38}, {0x28,0x3e}, {0x2c,0x3c}, {0x30,0x3a}, {0x34,0x40}, {0x3b,0x1266}, {0x3e,0xe748}, {0x4f,0x3a}, {0x62,0x42}, {0x70,0x32}, {0x7b,0x36}, {0x8f,0x34}, {0x96,0x1242}, {0x99,0x125a}, {0xa0,0x3a}, {0xa4,0x3c}, {0xa8,0x38}, {0xac,0x3e}, {0xb0,0x40}, {0xba,0x49}, {0xd0,0x125a}, {0xd3,0x1266} };
        for (int[] field : startupWords) {
            word(0x2200 + field[0], field[1]);
            comment(0x2200 + field[0], "stored startup binding WORD");
        }
        far(0x2207, 79, 0x2d7, 0x604d7);
        far(0x22b3, 78, 0x13, 0x5f813);
        relocation(0x2210, 3, 1, 5, 91);
        relocation(0x2249, 3, 1, 5, 30);
        relocation(0x2252, 3, 1, 7, 5);
        relocation(0x2265, 3, 1, 5, 132);
        conversion(0x2200, 0xbf, 0x3eeb);
        conversion(0x2200, 0xc4, 0x3f00);
        conversion(0x2200, 0xe9, 0x3eeb);
        comment(0x2200, "55 unequal bytes");
        comment(0x2200, "not assigned an invented complete function extent");
        comment(0x22dd, "No noreturn");
        // Automatic analysis may independently create the genuine loader entry function.
        if (!automatic) {
            countFunctions(0x2200, 0x237a, 6);
        }
        result.append("STARTUP: CODE378 correspondence, suffix136 shared;6 complete functions,4 selected internal/entry labels;DATA70 partial;22 stored WORDs+6 native FAR bindings+3 converted windows checked. No full startup prototype.\n");

        function(0x5024, 0x5069, 10);
        function(0x5069, 0x5090, 0);
        function(0x5090, 0x50b6, 0);
        reference(0x5077, 0x5024);
        reference(0x509e, 0x5024);
        word(0x5077, 0x2e24);
        word(0x509e, 0x2e24);
        conversion(0x2200, 0x2e3c, 0x1222);
        near(0x2200, 0x2e88, 0x200a);
        near(0x2200, 0x2eae, 0x200a);
        noRelocationFootprint(0x5024, 0x50b6);
        comment(0x5024, "13 differing bytes");
        result.append("SPRINTF:3 complete bodies69/39/38;all5 supplier binding owners/13 differing bytes;2 real engine CALL flows,2 callback offsets,1 converted memcpy relation. No modern va_list/full formatting ABI.\n");

        vprinterOwnership(output);
        label(0x41f2, "simtower_vprinter_conversion_cluster24");
        array(0x469b, 24, 2);
        int[] targets = {0x20f9,0x20e3,0x212e,0x20ee,0x215c,0x2169,0x21a7,0x21ae,0x21b3,0x2117,0x21dc,0x21ba,0x21be,0x21c2,0x223c,0x22e9,0x228c,0x22ac,0x242d,0x2469,0x2469,0x2469,0x2109,0x210f};
        for (int i = 0; i < targets.length; i++) {
            word(0x469b + 2L * i, targets[i]);
            reference(0x469b + 2L * i, 0x2200 + targets[i]);
        }
        reference(0x42de, 0x469b);
        word(0x42de, 0x249b);
        word(0x42cf, 0xb63);
        word(0x44d9, 0xb5c);
        near(0x2200, 0x222a, 0x3276);
        near(0x2200, 0x2325, 0x3417);
        array(0x65b5c, 7, 1);
        array(0x65b63, 96, 1);
        byte[] nullText = "(null)\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        require(Arrays.equals(nullText, Arrays.copyOfRange(original, 0x65b5c, 0x65b63)), "Actual literal NULL fallback bytes");
        noRelocationFootprint(0x41f2, 0x46cb);
        noRelocationFootprint(0x65b5c, 0x65bc3);
        comment(0x469b, "58 bytes");
        comment(0x442a, "unrecovered");
        result.append("VPRINTER:prefix24 label;1169-byte regional correspondence =main1095+scanner13+emitter entry9+flush/shared tail52, not one exclusive function. All13 helper CALLs, main jump-over, emitter conditional/fallthrough and single shared RET checked;24 WORD table DATA references,DATA7+96;all29 binding owners/58 differing bytes retained. LONGTOA/REALCVT and callback effects unresolved;private helpers are not additional vendor publics.\n");

        int[][] exitBodies = { {0x606a,0x606f,0}, {0x606f,0x60eb,6}, {0x60eb,0x6100,0}, {0x6100,0x6115,0}, {0x6115,0x6123,0}, {0x6123,0x6131,0} };
        for (int[] body : exitBodies) {
            function(body[0], body[1], body[2]);
        }
        structure("ExitData14Partial", 14, new int[] {0,4,8,12}, new int[] {4,4,4,2});
        data(0x66036, 14);
        for (int i = 0; i < 3; i++) {
            far(0x66036 + 4L * i, 1, 0x3e6a, 0x606a);
        }
        relocation(0x6087, 3, 1, 5, 48);
        for (int[] field : new int[][] { {0x1a,0x3a}, {0x28,0x1042}, {0x2f,0x1042}, {0x37,0x1034}, {0x3b,0x1034}, {0x42,0xe6c8}, {0x46,0x1034}, {0x52,0x1036}, {0x6c,0x103a}, {0x70,0x103e} }) {
            word(0x606a + field[0], field[1]);
            comment(0x606a + field[0], "Stored placement correspondence only");
        }
        for (int[] call : new int[][] { {0x3eb5,0xc9}, {0x3ebe,0xdc}, {0x3ec3,0xdb}, {0x3edf,0xdd} }) {
            conversion(0x2200, call[0], call[1]);
        }
        result.append("EXIT:6 complete body candidates/199bytes,DATA14 partial incl.3 native FAR storage bindings+guard;all15 CODE binding owners checked. Last2 incoming-name contexts unproved;wrapper bytes do not prove noreturn.\n");

        int[][] xxvBodies = { {0,0xa}, {0xa,0x66}, {0x90,0x143}, {0x143,0x14c}, {0x14c,0x1a8}, {0x1a8,0x22b}, {0x22b,0x27f}, {0x27f,0x2d7}, {0x2d7,0x351} };
        for (int[] body : xxvBodies) {
            function(0x60200 + body[0], 0x60200 + body[1], Function.UNKNOWN_STACK_DEPTH_CHANGE);
        }
        array(0x60266, 42, 1);
        structure("XxvInitialized296Partial", 296, new int[] {0xa,0xe,0x12,0x14}, new int[] {4,4,2,2});
        data(0x657ec, 296);
        var xxvData = (Structure) currentProgram.getDataTypeManager().getDataType(SimTowerRuntimeProfile.TYPES, "XxvInitialized296Partial");
        require(ghidra.program.model.data.Undefined.isUndefined(xxvData.getComponentAt(0).getDataType()), "A public label alone must not invent a CPPexceptionList field type");
        require(ghidra.program.model.data.Undefined.isUndefined(xxvData.getComponentAt(0xa8).getDataType()), "Static buffer public extent/type remains undefined");
        far(0x657f6, 79, 0, 0x60200);
        far(0x657fa, 79, 0x143, 0x60343);
        far(0x6026a, 79, 0x129, 0x60329);
        far(0x60288, 79, 0x66, 0x60266);
        for (int field : new int[] {0x15,0x3d,0xae,0xd3,0xec,0x102,0x157,0x17f,0x1b3,0x1d3,0x1ec,0x202,0x2fc,0x311,0x32c}) {
            far(0x60200 + field, 1, 0x1d4c, 0x3f4c);
        }
        for (int[] field : new int[][] { {3,0x3e26}, {0x132,0x3e26}, {0x222,0x3e26}, {0xa8,0x259e}, {0x2ef,0x1a55}, {0x304,0x1e47} }) {
            far(0x60200 + field[0], 1, field[1], 0x2200 + field[1]);
        }
        relocation(0x6029a, 2, 0, 79, 0);
        relocation(0x6029d, 5, 0, 79, 0x7e);
        for (int[] field : new int[][] { {0x2db,0x940}, {0x2e6,0xe6bc}, {0x2ea,0xe6be}, {0x2f5,0xe6be}, {0x2f8,0xe6bc}, {0x30a,0x944}, {0x30d,0x942}, {0x349,0x800}, {0x34c,0x7fe} }) {
            word(0x60200 + field[0], field[1]);
        }
        for (int[] call : new int[][] { {0x9f,0x3649}, {0x12c,0x1a58}, {0x139,0x36ba} }) {
            conversion(0x60200, call[0], call[1]);
        }
        String[] dataNames = {"CPPexceptionList","exceptFlags","savedDS","savedSI","terminatePTR","unexpectdPTR","terminate_DS","unexpectd_DS","throwFileName","throwLineNumber","throwExceptionName","exceptStaticBuffP","exceptMemAllocVars","exceptionNameBuff","ExceptStaticXbuff"};
        int[] dataOffsets = {0,4,6,8,0xa,0xe,0x12,0x14,0x16,0x1a,0x1c,0x20,0x24,0x28,0xa8};
        for (int i = 0; i < dataNames.length; i++) {
            label(0x657ec + dataOffsets[i], "simtower_crt45_candidate_" + dataNames[i]);
        }
        comment(0x657ec, "no established original placement");
        comment(0x60266, "not25 code functions");
        countFunctions(0x60200, 0x60551, 9);
        require(!currentProgram.getSymbolTable().getSymbols("simtower_crt45_candidate_DestructorCountPtr").hasNext(), "No fabricated BSS placement");
        result.append("XXV:9 complete code-entry regions/807bytes +42 raw DATA bytes =849;15 DATA public labels in296-byte partial contribution;all37 CODE binding owners+2 native DATA FAR bindings checked. Cleanup UNKNOWN;25 publics are not25 functions;BSS4 unplaced.\n");
        require(functions == 28, "Selected native function coverage must equal6+3+4+6+9, not XXV public count or regional spans");
        result.append("Selected functions checked: ").append(functions).append("; qualified DATA references checked: ").append(dataReferences).append(".\n");

        int types = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        int refs = currentProgram.getReferenceManager().getReferenceCountTo(context.mapped(0x60343));
        String before = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x2200));
        repeat();
        require(types == currentProgram.getDataTypeManager().getDataTypeCount(true), "Repeat must not duplicate datatypes");
        require(symbols == currentProgram.getSymbolTable().getNumSymbols(), "Repeat must not duplicate labels");
        require(refs == currentProgram.getReferenceManager().getReferenceCountTo(context.mapped(0x60343)), "Repeat must not duplicate selected references");
        require(before.equals(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x2200))), "Repeat must not duplicate profile comments");
        currentFunctionPreservation();
        Function guarded = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x5069));
        guarded.setName("user_owned_simtower_sprintf", SourceType.USER_DEFINED);
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        String signature = guarded.getPrototypeString(true, true);
        AddressSet body = new AddressSet(guarded.getBody());
        String userComment = "User annotation preserved by exact-image profile.";
        currentProgram.getListing().setComment(context.mapped(0x5069), CommentType.PLATE, userComment);
        repeat();
        require(signature.equals(guarded.getPrototypeString(true, true)) && body.equals(guarded.getBody()) && guarded.getSignatureSource() == SourceType.USER_DEFINED, "Actual user-owned function/signature/body must survive reapplication");
        require(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x5069)).startsWith(userComment), "User comment must survive reapplication");
        result.append("Repeat: stable datatypes/labels/selected references/comment; actual user-owned function/signature/body/comment preserved. Disposable validation Program retains deliberate user annotation.\n");
        manualVprinterPreservation();
        dataPreservation();
        result.append("Limits: no game/CRT execution, candidate link, historical toolchain attribution, complete formatting/exception effects, modern prototypes or arbitrary BSS placement. Far-copy/F_SCOPY stronger contracts separately owned.\n");
        result.append(log).append('\n');
        Files.writeString(output.resolve("simtower-runtime-profile-validation.txt"), result);
        println("SIMTOWER RUNTIME PROFILE VALIDATION PASS: " + args[2] + ";28 selected native functions by group, VPRINTER regional versus primary/helper ownership and all13 real helper CALLs/shared tail, code/data/file mapping and all selected binding owners, changed-current-code/context refusal and relocated-field checking, repeat and manual VPRINTER flow/signature preservation. " + output);
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

    private void repeat() throws Exception {
        if (automatic) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production repeated profile analysis failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.prepareData(context, monitor, log);
            profile.applyFinalFacts(context, monitor, log);
        }
    }

    private String refusedCurrentFacts(String reason) throws Exception {
        require(profile.match(currentProgram, monitor) != null, "Original FileBytes identity must still qualify after the deliberate current-code change");
        String refusal;
        if (automatic) {
            MessageLog preparation = new MessageLog();
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, preparation), "Data preparation must succeed; final function qualification must decide this scenario: " + preparation);
            refusal = collectProfileChanges();
            require(!refusal.contains("Applied " + profile.id() + " final facts") && !refusal.contains("native boundaries/data/bindings applied"), "Refused current code must not report final success: " + refusal);
        }
        else {
            refusal = "";
            try {
                profile.applyFinalFacts(context, monitor, new MessageLog());
            }
            catch (IllegalStateException conflict) {
                refusal = conflict.getMessage();
            }
        }
        require(refusal.contains("preserving current code") && refusal.contains(reason), "Current-code refusal must be visible for " + reason + ": " + refusal);
        return refusal;
    }

    private void decodeFixture(ghidra.program.model.address.Address start, ghidra.program.model.address.Address end) {
        DisassembleCommand decode = new DisassembleCommand(start, new AddressSet(start, end), false);
        decode.enableCodeAnalysis(false);
        require(decode.applyTo(currentProgram, monitor), "Decode only the deliberately modified native instruction: " + decode.getStatusMsg());
    }

    private void currentFunctionPreservation() throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        Function main = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x420a));
        AddressSet mainBody = new AddressSet(main.getBody());
        var terminal = context.mapped(0x4698);
        require(memory.getByte(terminal) == (byte) 0xc2 && memory.getShort(terminal.add(1)) == 12, "Actual VPRINTER terminal RET12 is the baseline, not a synthetic instruction");
        listing.clearCodeUnits(terminal, terminal.add(2), false);
        memory.setByte(terminal.add(1), (byte) 0);
        decodeFixture(terminal, terminal.add(2));
        main.setStackPurgeSize(0);
        String comment = listing.getComment(CommentType.PLATE, main.getEntryPoint());
        String refusal = refusedCurrentFacts("current byte differs");
        require(main.getStackPurgeSize() == 0 && mainBody.equals(main.getBody()) && memory.getShort(terminal.add(1)) == 0 && listing.getInstructionAt(terminal).getScalar(0).getUnsignedValue() == 0, "Reapplication must preserve current RET0, native instruction, body and purge0 despite unchanged original identity");
        require(comment.equals(listing.getComment(CommentType.PLATE, main.getEntryPoint())), "Refusal must not append a false function-contract success comment");
        result.append("CURRENT RET0: actual FILE4699 changed12->0, redecoded only terminal RET; original identity still true; native RET0/body/purge0 preserved, no final-success log. Refusal: ").append(refusal).append('\n');
        listing.clearCodeUnits(terminal, terminal.add(2), false);
        memory.setByte(terminal.add(1), (byte) 12);
        decodeFixture(terminal, terminal.add(2));
        repeat();
        require(main.getStackPurgeSize() == 12, "Restored original RET12 must qualify again");

        for (String registerName : new String[] {"opsize", "addrsize"}) {
            var register = currentProgram.getRegister(registerName);
            listing.clearCodeUnits(terminal, terminal.add(2), false);
            currentProgram.getProgramContext().setValue(register, terminal, terminal.add(2), BigInteger.ONE);
            decodeFixture(terminal, terminal.add(2));
            main.setStackPurgeSize(0);
            refusal = refusedCurrentFacts("effective operand/address context is not 16-bit");
            require(main.getStackPurgeSize() == 0 && mainBody.equals(main.getBody()) && BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(register, terminal, false)), "Changed current " + registerName + " and function facts must survive refusal");
            result.append("CURRENT CONTEXT ").append(registerName).append("=1 preserved with body/purge0; original identity still true; no final-success log. Refusal: ").append(refusal).append('\n');
            listing.clearCodeUnits(terminal, terminal.add(2), false);
            currentProgram.getProgramContext().setValue(register, terminal, terminal.add(2), BigInteger.ZERO);
            decodeFixture(terminal, terminal.add(2));
            repeat();
        }

        // This is an actual native loader-applied imported FAR field, not a mock relocation or an exempt byte range.
        var field = context.mapped(0x6087);
        relocation(0x6087, 3, 1, 5, 48);
        var instruction = listing.getInstructionContaining(field);
        var start = instruction.getMinAddress();
        var end = instruction.getMaxAddress();
        byte loaded = memory.getByte(field);
        require(loaded != context.original().getOriginalByte(0x6087), "Real relocation must have changed the original chain terminator");
        Function helper = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x606f));
        AddressSet helperBody = new AddressSet(helper.getBody());
        listing.clearCodeUnits(start, end, false);
        byte changed = (byte) (loaded ^ 1);
        memory.setByte(field, changed);
        decodeFixture(start, end);
        helper.setStackPurgeSize(0);
        refusal = refusedCurrentFacts("current byte differs");
        require(refusal.contains("FILE 6087") && memory.getByte(field) == changed && helper.getStackPurgeSize() == 0 && helperBody.equals(helper.getBody()) && listing.getInstructionAt(start) != null, "APPLIED relocation must not hide a current operand patch or reapply original purge6");
        result.append("CURRENT RELOCATION: real imported FAR FILE6087 patched after native load; APPLIED metadata retained, original identity still true; patched instruction/body/purge0 preserved; no final-success log. Refusal: ").append(refusal).append('\n');
        listing.clearCodeUnits(start, end, false);
        memory.setByte(field, loaded);
        decodeFixture(start, end);
        repeat();
        require(helper.getStackPurgeSize() == 6 && main.getStackPurgeSize() == 12, "Restored actual loader fields and contexts must qualify again");
    }

    private void manualVprinterPreservation() throws Exception {
        Function main = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x420a));
        var jump = currentProgram.getListing().getInstructionAt(context.mapped(0x4222));
        // Install a stable manual fixture without queuing unrelated native body re-inference before the profile's final stage.
        require(AutoAnalysisManager.getAnalysisManager(currentProgram).scheduleWorker(new AnalysisWorker() {
            public String getWorkerName() {
                return "Install manual VPRINTER preservation fixture";
            }
            public boolean analysisWorkerCallback(Program program, Object ignored, TaskMonitor workerMonitor) throws Exception {
                main.setName("user_owned_simtower_VPRINTER", SourceType.USER_DEFINED);
                main.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
                jump.setFlowOverride(FlowOverride.CALL_RETURN);
                return true;
            }
        }, null, false, monitor), "Install manual VPRINTER fixture in native suppressed-event worker");
        String signature = main.getPrototypeString(true, true);
        AddressSet body = new AddressSet(main.getBody());
        int[] before = Arrays.stream(jump.getPcode(true)).mapToInt(PcodeOp::getOpcode).toArray();
        require(Arrays.stream(before).anyMatch(op -> op == PcodeOp.CALL) && Arrays.stream(before).anyMatch(op -> op == PcodeOp.RETURN), "Deliberate manual VPRINTER override must actually produce effective CALL/RETURN pcode");
        repeat();
        require(signature.equals(main.getPrototypeString(true, true)) && body.equals(main.getBody()) && main.getSignatureSource() == SourceType.USER_DEFINED, "Actual manual VPRINTER body/signature must survive production reapplication: before=" + body + " / " + signature + "; after=" + main.getBody() + " / " + main.getPrototypeString(true, true));
        require(jump.getFlowOverride() == FlowOverride.CALL_RETURN && Arrays.equals(before, Arrays.stream(jump.getPcode(true)).mapToInt(PcodeOp::getOpcode).toArray()), "Preserved VPRINTER must retain its intentional override and effective CALL/RETURN pcode, not receive dependent main-flow cleanup");
        result.append("MANUAL VPRINTER: USER_DEFINED body/signature and intentional FILE4222 CALL_RETURN override/effective CALL+RETURN pcode all survive actual reapplication.\n");
    }

    private void dataPreservation() throws Exception {
        var address = context.mapped(0x65030);
        var listing = currentProgram.getListing();
        DataType expected = listing.getDefinedDataAt(address).getDataType();
        var symbols = currentProgram.getSymbolTable();
        var references = currentProgram.getReferenceManager();
        var symbol = symbols.createLabel(address.add(1), "validation_equivalent_data", SourceType.USER_DEFINED);
        var reference = references.addMemoryReference(address, context.mapped(0x2200), RefType.DATA, SourceType.USER_DEFINED, 0);
        var before = references.getReferencesFrom(address);
        context.data(0x65030, expected);
        require(listing.getDefinedDataAt(address).getDataType().isEquivalent(expected) && Arrays.equals(before, references.getReferencesFrom(address)) && symbol.getSource() == SourceType.USER_DEFINED, "Equivalent exact data must remain untouched, including higher-priority label and reference");
        symbol.delete();
        references.delete(reference);
        result.append("DATA equivalent: exact70-byte type/extent, USER_DEFINED label and outgoing reference preserved without clearing.\n");

        dataConflict(expected, "crossing", -2, 74, 0, false);
        dataConflict(expected, "unsymbolized", 0, 70, -1, true);
        dataConflict(expected, "tail", 68, 4, -1, false);
        dataConflict(expected, "inside_symbol", 0, 70, 1, false);
    }

    private void dataConflict(DataType expected, String name, int delta, int length, int symbolOffset, boolean analyzer) throws Exception {
        var listing = currentProgram.getListing();
        var target = context.mapped(0x65030);
        var start = target.add(delta);
        var end = start.add(length - 1);
        var references = currentProgram.getReferenceManager();
        listing.clearCodeUnits(target.subtract(2), target.add(71), false);
        var type = new StructureDataType("Validation_manual_" + name, length);
        listing.createData(start, type);
        var symbol = symbolOffset < 0 ? null : currentProgram.getSymbolTable().createLabel(start.add(symbolOffset), "validation_manual_" + name, SourceType.USER_DEFINED);
        references.addMemoryReference(start, context.mapped(0x2200), RefType.DATA, SourceType.USER_DEFINED, 0);
        references.addMemoryReference(end, context.mapped(0x2201), RefType.DATA, SourceType.USER_DEFINED, 0);
        var firstReferences = references.getReferencesFrom(start);
        var lastReferences = references.getReferencesFrom(end);
        String refusal = null;
        try {
            context.data(0x65030, expected);
        }
        catch (IllegalStateException conflict) {
            refusal = conflict.getMessage();
        }
        require(refusal != null && refusal.contains("preserving"), "Conflicting native data must be visibly refused: " + name);
        if (analyzer) {
            MessageLog conflictLog = new MessageLog();
            require(!new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, conflictLog), "Production analyzer must report conflicting data as failure, not successful application");
            require(conflictLog.toString().contains("preserving conflicting defined data") && !conflictLog.toString().contains("Applied " + profile.id()), "Production conflict log must expose refusal without success: " + conflictLog);
        }
        var preserved = listing.getDefinedDataAt(start);
        require(preserved != null && preserved.getLength() == length && preserved.getMaxAddress().equals(end) && preserved.getDataType().isEquivalent(type), "Full conflicting type/extent must survive: " + name);
        require(Arrays.equals(firstReferences, references.getReferencesFrom(start)) && Arrays.equals(lastReferences, references.getReferencesFrom(end)), "References at both ends of conflicting unit must survive: " + name);
        require(symbol == null || symbol.getSource() == SourceType.USER_DEFINED, "Manual symbol must survive: " + name);
        result.append("DATA ").append(name).append(": ").append(start).append(" through ").append(end).append(" length=").append(length).append(";type,full extent,both outgoing references and manual symbol preserved;refusal=").append(refusal).append(";production refusal checked=").append(analyzer).append('\n');
        if (symbol != null) {
            symbol.delete();
        }
        // Remove only the deliberately installed fixture, then restore the supported profile datum.
        listing.clearCodeUnits(start, end, false);
        context.data(0x65030, expected);
    }

    private void mapping(int ordinal, long start, int length) {
        AddressSet range = context.range(start, start + length);
        int descriptor = 0x290 + 8 * (ordinal - 1);
        try {
            int sector = Byte.toUnsignedInt(context.original().getOriginalByte(descriptor)) | Byte.toUnsignedInt(context.original().getOriginalByte(descriptor + 1)) << 8;
            int base = sector << 9;
            var nativeAddress = (ghidra.program.model.address.SegmentedAddress) range.getMinAddress();
            require(nativeAddress.getSegmentOffset() == start - base, "Native NE-relative offset must agree with original descriptor/file coordinate");
        }
        catch (Exception e) {
            throw new IllegalStateException("Mapping failed at original FILE " + Long.toHexString(start), e);
        }
        result.append("MAP NE").append(ordinal).append(" FILE[").append(Long.toHexString(start)).append(',').append(Long.toHexString(start + length)).append(") -> ").append(range).append('\n');
    }

    private void function(long start, long end, int purge) {
        function(start, context.range(start, end), purge);
    }

    private void function(long start, AddressSet body, int purge) {
        Function f = currentProgram.getFunctionManager().getFunctionAt(context.mapped(start));
        require(f != null && f.getBody().equals(body), "Qualified native exclusive function body at FILE " + Long.toHexString(start));
        require(f.getStackPurgeSize() == purge, "Native argument cleanup, not total frame delta, at " + f.getEntryPoint());
        int count = 0;
        for (var part : body) {
            var cursor = part.getMinAddress();
            while (cursor.compareTo(part.getMaxAddress()) <= 0) {
                var instruction = currentProgram.getListing().getInstructionAt(cursor);
                require(instruction != null && instruction.getMaxAddress().compareTo(part.getMaxAddress()) <= 0, "Complete native instruction ownership at " + cursor);
                cursor = cursor.add(instruction.getLength());
                count++;
            }
        }
        functions++;
        result.append("FUNCTION FILE entry ").append(Long.toHexString(start)).append(" native body ").append(body).append(" bytes=").append(body.getNumAddresses()).append(" cleanup=").append(purge).append(" instructions=").append(count).append('\n');
    }

    private void vprinterOwnership(Path output) throws Exception {
        AddressSet primary = context.range(0x420a, 0x4224);
        primary.add(context.range(0x426e, 0x469b));
        function(0x420a, primary, 12);
        function(0x4224, 0x4231, Function.UNKNOWN_STACK_DEPTH_CHANGE);
        function(0x4231, 0x423a, Function.UNKNOWN_STACK_DEPTH_CHANGE);
        function(0x423a, 0x426e, Function.UNKNOWN_STACK_DEPTH_CHANGE);
        require(primary.getNumAddresses() == 1095 && !primary.intersects(context.range(0x4224, 0x426e)), "Regional1169 must not make main own independently called helper74");
        countFunctions(0x420a, 0x469b, 4);
        require(currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x426e)) == null, "Main native continuation belongs to the same prologue/frame, not a synthetic separate callee");
        var jump = currentProgram.getListing().getInstructionAt(context.mapped(0x4222));
        require(jump != null && jump.getFlowType().isJump() && Arrays.asList(jump.getFlows()).contains(context.mapped(0x426e)), "Actual main JMP2022 must skip all74 helper bytes");
        require(jump.getFlowOverride() == FlowOverride.NONE && Arrays.stream(jump.getPcode(true)).anyMatch(op -> op.getOpcode() == PcodeOp.BRANCH && op.getInput(0).getAddress().equals(context.mapped(0x426e))), "Effective JMP2022 must remain BRANCH206e, not a stale synthetic CALL_RETURN boundary");
        require(context.original().getOriginalByte(0x4222) == (byte) 0xeb && context.original().getOriginalByte(0x4223) == (byte) 0x4a, "Literal original jump-over operand");
        int[][] helperCalls = { {0x22db,0x2024}, {0x233b,0x2024}, {0x236d,0x2024}, {0x23c1,0x2031}, {0x23d2,0x2031}, {0x23d8,0x2031}, {0x23f7,0x2031}, {0x2402,0x2031}, {0x2425,0x2031}, {0x2474,0x2031}, {0x2090,0x203a}, {0x2418,0x203a}, {0x2483,0x203a} };
        for (int[] call : helperCalls) {
            near(0x2200, call[0], call[1]);
        }
        var branch = currentProgram.getListing().getInstructionAt(context.mapped(0x4238));
        require(branch != null && branch.getFlowType().isConditional() && Arrays.asList(branch.getFlows()).contains(context.mapped(0x426d)) && context.mapped(0x423a).equals(branch.getFallThrough()), "Emitter entry must retain both conditional shared RET and fallthrough into flush");
        var sharedReturn = currentProgram.getListing().getInstructionAt(context.mapped(0x426d));
        Function flush = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x423a));
        require(sharedReturn != null && sharedReturn.getFlowType().isTerminal() && context.original().getOriginalByte(0x426d) == (byte) 0xc3 && currentProgram.getFunctionManager().getFunctionContaining(sharedReturn.getAddress()) == flush, "One physical shared near RET206d remains owned by native flush partition");
        label(0x426d, "simtower_vprinter_emit_flush_shared_ret");
        comment(0x4231, "not a standalone returning nine-byte helper");
        var callback = currentProgram.getListing().getInstructionAt(context.mapped(0x4251));
        require(callback != null && callback.getFlowType().isCall() && callback.getFlowType().isComputed(), "Real parent-frame indirect callback2051 must remain native code");
        // Native High/C is observed, not promoted into a callback ABI or recovered formatter semantics.
        AddressSet continuation = context.range(0x426e, 0x469b);
        DecompInterface decomp = new DecompInterface();
        require(decomp.openProgram(currentProgram), "Open actual SimTower Program for native C/High observation");
        try {
            for (int entry : new int[] {0x200a,0x2024,0x2031,0x203a}) {
                Function f = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x2200 + entry));
                var d = decomp.decompileFunction(f, 60, monitor);
                require(d.decompileCompleted() && d.getHighFunction() != null && d.getDecompiledFunction() != null, "Native C/High must be available for actual VPRINTER entry " + Integer.toHexString(entry) + ": " + d.getErrorMessage());
                Files.writeString(output.resolve("vprinter-" + Integer.toHexString(entry) + ".c"), d.getDecompiledFunction().getC());
                StringBuilder high = new StringBuilder();
                int indirectCalls = 0;
                var privateCalls = new HashSet<Integer>();
                boolean continuationCode = false;
                var ops = d.getHighFunction().getPcodeOps();
                while (ops.hasNext()) {
                    var op = ops.next();
                    high.append(op.getSeqnum().getTarget()).append(' ').append(op).append('\n');
                    if (continuation.contains(op.getSeqnum().getTarget())) {
                        continuationCode = true;
                    }
                    if (entry == 0x200a && op.getOpcode() == PcodeOp.CALL) {
                        require(!op.getInput(0).getAddress().equals(context.mapped(0x426e)), "Native main High must not retain a synthetic continuation callee206e");
                        for (int[] call : helperCalls) {
                            if (op.getSeqnum().getTarget().equals(context.mapped(0x2200 + call[0]))) {
                                require(op.getInput(0).getAddress().equals(context.mapped(0x2200 + call[1])), "Native main High private CALL target must match actual instruction NE1:" + Integer.toHexString(call[0]));
                                privateCalls.add(call[0]);
                                break;
                            }
                        }
                    }
                    if (op.getOpcode() == PcodeOp.CALLIND && op.getSeqnum().getTarget().equals(context.mapped(0x4251))) {
                        indirectCalls++;
                    }
                }
                if (entry == 0x2031 || entry == 0x203a) {
                    require(indirectCalls == 1, "Native High must traverse the actual shared flush callback once, including emitter's shared suffix; not duplicate physical code");
                }
                if (entry == 0x200a) {
                    require(continuationCode && privateCalls.size() == 13, "Native main C/High must contain the joined primary continuation and all13 correct private CALL targets");
                }
                Files.writeString(output.resolve("vprinter-" + Integer.toHexString(entry) + ".high.txt"), high);
                result.append("VPRINTER native C/High entry ").append(Integer.toHexString(entry)).append(" exclusive-body-bytes=").append(f.getBody().getNumAddresses()).append(" private-CALLs=").append(privateCalls.size()).append(" shared-callback-CALLIND=").append(indirectCalls).append(" diagnostic=").append(d.getErrorMessage()).append('\n');
            }
        }
        finally {
            decomp.dispose();
        }
        result.append("Native emitter High follows real conditional/fallthrough shared tail beyond its9-byte exclusive function body. This supports entry/tail representation, not standalone C prototypes, callback effects, cleanup or full formatting semantics.\n");
    }

    private void countFunctions(long start, long end, int expected) {
        int count = 0;
        for (var iterator = currentProgram.getFunctionManager().getFunctions(context.range(start, end), true); iterator.hasNext();) {
            iterator.next();
            count++;
        }
        require(count == expected, "Selected native function count at FILE " + Long.toHexString(start) + ": " + count + " versus " + expected);
    }

    private void data(long start, int length) {
        var d = currentProgram.getListing().getDefinedDataAt(context.mapped(start));
        require(d != null && d.getLength() == length, "Native DATA extent at FILE " + Long.toHexString(start));
        require(!currentProgram.getListing().getInstructions(context.range(start, start + length), true).hasNext(), "Raw table/DATA must not be disassembled instructions");
        require(!currentProgram.getFunctionManager().getFunctionsOverlapping(context.range(start, start + length)).hasNext(), "Raw table/DATA must not belong to a function");
    }

    private void array(long start, int count, int width) {
        data(start, count * width);
        var type = currentProgram.getListing().getDefinedDataAt(context.mapped(start)).getDataType();
        require(type instanceof Array && ((Array) type).getNumElements() == count && ((Array) type).getElementLength() == width, "Native array count/element width");
    }

    private void structure(String name, int length, int[] offsets, int[] widths) {
        var type = currentProgram.getDataTypeManager().getDataType(SimTowerRuntimeProfile.TYPES, name);
        require(type instanceof Structure && type.getLength() == length, "Native partial structure " + name);
        for (int i = 0; i < offsets.length; i++) {
            var field = ((Structure) type).getComponentAt(offsets[i]);
            require(field != null && field.getOffset() == offsets[i] && field.getLength() == widths[i], "Qualified field " + name + "+" + offsets[i]);
        }
    }

    private void label(long file, String name) {
        require(currentProgram.getSymbolTable().getSymbol(name, context.mapped(file), currentProgram.getGlobalNamespace()) != null, "Qualified label " + name);
    }

    private void comment(long file, String text) {
        String actual = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(file));
        require(actual != null && actual.contains(text), "Qualified annotation at FILE " + Long.toHexString(file) + ": " + text);
    }

    private void word(long source, int expected) throws Exception {
        int actual = Byte.toUnsignedInt(context.original().getOriginalByte(source)) | Byte.toUnsignedInt(context.original().getOriginalByte(source + 1)) << 8;
        require(actual == expected, "Literal original WORD FILE " + Long.toHexString(source));
    }

    private void reference(long source, long target) {
        var ref = currentProgram.getReferenceManager().getReference(context.mapped(source), context.mapped(target), 0);
        require(ref != null && ref.getReferenceType() == RefType.DATA, "Qualified DATA relation, not fabricated unconditional CALL");
        dataReferences++;
    }

    private void relocation(long source, int type, int flags, int segment, int offset) {
        require(currentProgram.getRelocationTable().getRelocations(context.mapped(source)).stream().anyMatch(r -> {
            long[] values = r.getValues();
            return r.getStatus() == Relocation.Status.APPLIED && r.getType() == type && values != null && values.length == 5 && values[1] == flags && values[3] == segment && values[4] == offset;
        }), "Native applied relocation metadata at FILE " + Long.toHexString(source));
    }

    private void far(long source, int segment, int offset, long target) throws Exception {
        relocation(source, 3, 0, segment, offset);
        reference(source, target);
        var address = context.mapped(target);
        int loadedOffset = Short.toUnsignedInt(currentProgram.getMemory().getShort(context.mapped(source)));
        int selector = Short.toUnsignedInt(currentProgram.getMemory().getShort(context.mapped(source).add(2)));
        var space = (ghidra.program.model.address.SegmentedAddressSpace) address.getAddressSpace();
        require(space.getAddress(selector, loadedOffset).equals(address), "Loaded FAR storage must agree with original-file qualified target");
    }

    private void near(long base, int call, int target) throws Exception {
        require(context.original().getOriginalByte(base + call) == (byte) 0xe8, "Actual near CALL opcode");
        word(base + call + 1, (target - call - 3) & 0xffff);
        var instruction = currentProgram.getListing().getInstructionAt(context.mapped(base + call));
        // Startup stays a qualified entry fragment; selected complete function bodies must have real native flows.
        if (currentProgram.getFunctionManager().getFunctionContaining(context.mapped(base + call)) != null) {
            require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(context.mapped(base + target)), "Real native near CALL must resolve to qualified target");
        }
    }

    private void conversion(long base, int start, int target) throws Exception {
        require(context.original().getOriginalByte(base + start) == (byte) 0x90 && context.original().getOriginalByte(base + start + 1) == (byte) 0x0e, "Complete original NOP/PUSH-CS converted-call window");
        near(base, start + 2, target);
        noRelocationFootprint(base + start, base + start + 5);
        comment(base + start, "complete five-byte NOP/PUSH CS/near CALL window");
    }

    private void noRelocationFootprint(long start, long end) {
        // Iterate all native records, including a source immediately before the selected interval.
        AddressSet selected = context.range(start, end);
        for (var iterator = currentProgram.getRelocationTable().getRelocations(); iterator.hasNext();) {
            var relocation = iterator.next();
            int width = switch (relocation.getType()) { case 0 -> 1; case 2, 5 -> 2; case 3 -> 4; default -> 1; };
            var footprint = new AddressSet(relocation.getAddress(), relocation.getAddress().add(width - 1));
            require(!footprint.intersects(selected), "Unexpected native relocation footprint intersects qualified raw range");
        }
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
