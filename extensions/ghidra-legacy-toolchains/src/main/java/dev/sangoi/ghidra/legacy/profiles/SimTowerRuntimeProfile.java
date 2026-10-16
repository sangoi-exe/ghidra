package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Exact supplied SIMTOWER image correspondence, not a general CRT/compiler signature. */
public final class SimTowerRuntimeProfile extends ToolchainProfile {
    public static final String ID = "simtower-runtime-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/SimTowerRuntime");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final long NE1 = 0x2200;
    private static final long NE79 = 0x60200;
    private static final long NE82 = 0x65000;
    private static final int UNKNOWN = Function.UNKNOWN_STACK_DEPTH_CHANGE;
    private static final String QUALIFICATION = "Source: SimTower windows-toolchain-fingerprints.md at e90bb42; retained C0WL45/same-model CWL45 members. Vendor correspondence candidates and descriptive analysis names, not original debug symbols, historical producer attribution, integral linkage or observed runtime effects.";

    public SimTowerRuntimeProfile() {
        // Named decoded original, literally equal to the documented installed guest copy; not relocated memory.
        super(ID, "New Executable (NE)", 6566400, "2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        startup(c);
        formatting(c);
        exit(c);
        exceptions(c);
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        body(c, NE1, 0xc9, 0xdb, "crt45_candidate_cleanup", 0, "SF02 complete cleanup FAR-return body; conditional dispatcher effects remain unproved.");
        body(c, NE1, 0xdb, 0xdc, "crt45_candidate_checknull", 0, "SF02 one-byte RETF public, not a noreturn assertion.");
        body(c, NE1, 0xdc, 0xdd, "crt45_candidate_restorezero", 0, "SF02 one-byte RETF public.");
        body(c, NE1, 0xf2, 0xf5, "crt45_candidate_GetDGROUP", 0, "SF02 supplier __GetDGROUP; MOV AX,SS; RETF. No invented return type.");
        body(c, NE1, 0xf5, 0x139, "startup_init_dispatch", 0, "SF02 complete near dispatcher; analysis name, not another vendor public. Six-byte record traversal and conditional near/FAR calls do not prove actual table population.");
        body(c, NE1, 0x139, 0x17a, "startup_exit_dispatch", 0, "SF02 complete near dispatcher; analysis name. Shared136-byte suffix is not release-discriminating.");
        body(c, NE1, 0x2e24, 0x2e69, "sprintf_copy_callback", 10, "SPRF01 near callback69; mutable destination-pair context and reread count, not a modern callback prototype. Same-library memcpy38 correspondence is separately owned by far-copy analysis.");
        body(c, NE1, 0x2e69, 0x2e90, "crt45_candidate_sprintf", 0, "SPRF01 FAR wrapper39; constructs SS-relative trailing argument cursor, initializes destination before later argument reads. No va_list, signed-return or pointer-validity assertion.");
        body(c, NE1, 0x2e90, 0x2eb6, "crt45_candidate_vsprintf", 0, "SPRF01 FAR wrapper38 reads supplied cursor WORD; not proof of modern va_list or complete formatting semantics.");
        // Ordinary native analysis independently owns the scanner13, emitter entry9 and flush52. The initial JMP skips all74 helper bytes; join the main entry and its native continuation, not the entire member region.
        var primary = c.range(NE1 + 0x200a, NE1 + 0x2024);
        primary.add(c.range(NE1 + 0x206e, NE1 + 0x249b));
        c.function(NE1 + 0x200a, primary, "simtower_crt45_candidate_VPRINTER", 12, QUALIFICATION + " SPRF02 [200a,249b)1169 is regional correspondence coverage, not exclusive function ownership. Main native body joins entry[200a,2024) and continuation[206e,249b),1095 bytes; JMP2022 skips independent helpers[2024,206e). Terminal LEAVE; RET0c precedes data. Complete engine effects/servicing remain unreviewed.");
        originalWord(c, NE1 + 0x2022, 0x4aeb);
        var mainJump = c.program().getListing().getInstructionAt(c.mapped(NE1 + 0x2022));
        if (mainJump.getFlowOverride() == FlowOverride.CALL_RETURN) {
            // Retained ordinary analysis had split206e into a function and changed this exact JMP into CALL/RETURN pcode. Its joined continuation must use the original branch, not a synthetic callee.
            mainJump.setFlowOverride(FlowOverride.NONE);
        }
        c.comment(NE1 + 0x2022, "SPRF02 original EB4A JMP ->206e joins the main continuation. Remove only this demonstrated stale CALL_RETURN override; no general flow-override cleanup.");
        c.function(NE1 + 0x2024, c.range(NE1 + 0x2024, NE1 + 0x2031), "simtower_vprinter_scan_entry", UNKNOWN, QUALIFICATION + " SPRF02 native scanner13; real near CALLs22db/233b/236d and RET2030. No register-result prototype or stronger cleanup inferred.");
        c.function(NE1 + 0x2031, c.range(NE1 + 0x2031, NE1 + 0x203a), "simtower_vprinter_emit_entry", UNKNOWN, QUALIFICATION + " SPRF02 native exclusive emitter entry9, not a standalone returning nine-byte helper. SS:[DI] store/increment, parent-frame BYTE[BP-14] decrement; conditional2038 reaches shared RET206d, otherwise falls through to flush entry203a. Shared tail[203a,206e) remains owned by the native flush function; no overlapping function, synthetic callee or net cleanup/prototype inferred.");
        c.function(NE1 + 0x203a, c.range(NE1 + 0x203a, NE1 + 0x206e), "simtower_vprinter_flush_entry", UNKNOWN, QUALIFICATION + " SPRF02 native flush52 shares RET206d with emitter entry2031. Parent BP/current-frame callback[BP+e] at2051 has unknown callee contract. Native exclusive partition does not make the emitter's shared suffix disjoint code or establish standalone C parameters, callback effects or net cleanup.");
        int[][] exitBodies = { {0x3e6a,0x3e6f,0}, {0x3e6f,0x3eeb,6}, {0x3eeb,0x3f00,0}, {0x3f00,0x3f15,0}, {0x3f15,0x3f23,0}, {0x3f23,0x3f31,0} };
        String[] exitNames = { "exit_dummy", "exit_local_helper", "exit", "_exit", "_cexit", "_c_exit" };
        for (int i = 0; i < exitBodies.length; i++) {
            int[] b = exitBodies[i];
            body(c, NE1, b[0], b[1], "crt45_candidate_" + exitNames[i], b[2], "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects." + (i >= 4 ? " Original incoming coverage for this name candidate unproved." : ""));
        }
        int[][] bodies = { {0,0xa}, {0xa,0x66}, {0x90,0x143}, {0x143,0x14c}, {0x14c,0x1a8}, {0x1a8,0x22b}, {0x22b,0x27f}, {0x27f,0x2d7}, {0x2d7,0x351} };
        String[] names = { "terminate", "set_terminate", "call_terminate", "unexpected", "set_unexpected", "call_unexpected", "GetPolymorphicDTC", "GetPolymorphicDTCfar", "ExceptInit" };
        String[] publics = { "@terminate$qv", "@set_terminate$qnqv$v", "___call_terminate", "@unexpected$qv", "@set_unexpected$qnqv$v", "___call_unexpected", "@__GetPolymorphicDTC$qnvui", "@__GetPolymorphicDTCfar$qnvui", "__ExceptInit" };
        for (int i = 0; i < bodies.length; i++) {
            body(c, NE79, bodies[i][0], bodies[i][1], "crt45_candidate_" + names[i], UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public " + publics[i] + ". Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN.");
        }
        log.appendMsg(ID, "Qualified startup, SPRINTF, VPRINTER, EXIT and XXV native boundaries/data/bindings applied. No complete CRT binding, historical compiler attribution, modern prototypes, noreturn or unknown BSS placement inferred.");
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private StructureDataType partial(String name, int length, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, length);
        type.setDescription(description + " Descriptive partial analysis layout, not a recovered C type. Unestablished fields remain undefined.");
        return type;
    }

    private DataType farStorage(Context c) {
        StructureDataType type = partial("FarStorage16", 4, "Native NE offset/selector storage; no pointee prototype or live selector resolution.");
        type.replaceAtOffset(0, WORD, 2, "offset", null);
        type.replaceAtOffset(2, WORD, 2, "selector", null);
        return resolve(c, type);
    }

    private void body(Context c, long base, int start, int end, String name, int cleanup, String qualification) throws Exception {
        c.function(base + start, base + end, "simtower_" + name, cleanup, QUALIFICATION + " " + qualification);
    }

    private void bytes(Context c, long start, int length, String name) throws Exception {
        c.data(start, new ArrayDataType(BYTE, length, 1));
        c.label(start, "simtower_" + name);
    }

    private void startup(Context c) throws Exception {
        c.range(NE1, NE1 + 0x17a);
        c.label(NE1, "simtower_c0wl45_startup_correspondence");
        c.comment(NE1, QUALIFICATION + " SF02/C0FP01 complete CODE378 has55 unequal bytes, all22 WORD operands, six FAR offsets and three complete converted-call windows. Not literal equality or a release-exclusive signature. Startup entry/shared termination flow is not assigned an invented complete function extent. Stable suffix [00f2,017a) is136 literal bytes shared with inspected3.1/4.5 releases.");
        for (int entry : new int[] { 0x56, 0xb2, 0xdd }) {
            c.label(NE1 + entry, "simtower_c0wl45_public_candidate_" + Integer.toHexString(entry));
        }
        c.comment(NE1 + 0x56, "Supplier public __INITAPPCALLED; an internal startup point, not an additional proved whole function.");
        c.comment(NE1 + 0xb2, "Supplier public __WINMAINCALL; internal startup point. Native FAR binding at00b3 targets NE78:0013; WINMAIN is a vendor candidate, not a retained original name.");
        c.comment(NE1 + 0xdd, "Supplier __terminate candidate; original DOS-interrupt/converted-call sequence [00dd,00f2). No noreturn or complete C prototype inferred.");
        StructureDataType data = partial("StartupData70Partial", 70, "SF02 complete initialized C0WL45 DATA70 literally equals NE82[0030,0076). Stored placement bias0030, not observed live DS.");
        int[] offsets = { 2, 4, 6, 8, 10, 12, 14, 16, 18, 25 };
        String[] names = { "protected_word", "processor_word", "coprocessor_word", "psp_word", "instance_word", "previous_instance_word", "command_offset_word", "show_word", "version_word", "abend_test_word" };
        for (int i = 0; i < offsets.length; i++) {
            data.replaceAtOffset(offsets[i], WORD, 2, names[i], "Stored operand/public correspondence only.");
        }
        data.replaceAtOffset(27, new ArrayDataType(BYTE, 43, 1), 43, "copyright_bytes", "Literal vendor DATA correspondence is not producer identity.");
        c.data(NE82 + 0x30, resolve(c, data));
        c.label(NE82 + 0x30, "simtower_c0wl45_initialized_data70");
        int[][] words = { {0x24,0x38}, {0x28,0x3e}, {0x2c,0x3c}, {0x30,0x3a}, {0x34,0x40}, {0x3b,0x1266}, {0x3e,0xe748}, {0x4f,0x3a}, {0x62,0x42}, {0x70,0x32}, {0x7b,0x36}, {0x8f,0x34}, {0x96,0x1242}, {0x99,0x125a}, {0xa0,0x3a}, {0xa4,0x3c}, {0xa8,0x38}, {0xac,0x3e}, {0xb0,0x40}, {0xba,0x49}, {0xd0,0x125a}, {0xd3,0x1266} };
        for (int[] field : words) {
            originalWord(c, NE1 + field[0], field[1]);
            c.comment(NE1 + field[0], "SF02 stored startup binding WORD -> NE82:" + Integer.toHexString(field[1]) + "; operand/boundary correspondence, not a resolved live DS reference or complete linker map.");
        }
        c.farReference(NE1 + 7, 79, 0x2d7, NE79 + 0x2d7);
        c.farReference(NE1 + 0xb3, 78, 0x13, 0x5f813);
        importedFar(c, NE1 + 0x10, 5, 91, "SF02 INITTASK candidate / KERNEL91");
        importedFar(c, NE1 + 0x49, 5, 30, "SF02 WAITEVENT candidate / KERNEL30");
        importedFar(c, NE1 + 0x52, 7, 5, "SF02 INITAPP candidate / USER5");
        importedFar(c, NE1 + 0x65, 5, 132, "SF02 GETWINFLAGS candidate / KERNEL132");
        for (int[] call : new int[][] { {0xbf,0x3eeb}, {0xc4,0x3f00}, {0xe9,0x3eeb} }) {
            converted(c, NE1, call[0], call[1], "SF02 startup FAR-to-near conversion");
        }
    }

    private void formatting(Context c) throws Exception {
        c.comment(NE1 + 0x2e24, "SPRF01 whole146-byte correspondence is not literal:13 differing bytes belong to five native supplier owners: one five-byte converted memcpy call, two callback offsets and two relative engine fields. No NE load-time relocation source intersects this region; actual candidate linkage unperformed.");
        converted(c, NE1, 0x2e3c, 0x1222, "SPRF01 supplier _memcpy; same-library CWL31/CWL45 bodies literally equal original38 bytes, not exclusive release attribution");
        offsetReference(c, NE1 + 0x2e77, 0x2e24, NE1 + 0x2e24, "SPRF01 callback offset, no selector/prototype inferred");
        offsetReference(c, NE1 + 0x2e9e, 0x2e24, NE1 + 0x2e24, "SPRF01 second callback offset");
        nearCall(c, NE1, 0x2e88, 0x200a, "SPRF01 supplier __VPRINTER dependency");
        nearCall(c, NE1, 0x2eae, 0x200a, "SPRF01 second __VPRINTER call");
        c.label(NE1 + 0x1ff2, "simtower_vprinter_conversion_cluster24");
        c.comment(NE1 + 0x1ff2, "SPRF02 literal conversion cluster24, shared across inspected releases; multiple near entries share a suffix, not24 bytes of separately proved public functions.");
        c.label(NE1 + 0x206d, "simtower_vprinter_emit_flush_shared_ret");
        c.comment(NE1 + 0x206d, "SPRF02 one physical RET, native owner flush203a; emitter2038 branches here. A shared tail relation, not duplicate code or a separate callee address.");
        c.data(NE1 + 0x249b, new ArrayDataType(WORD, 24, 2));
        c.label(NE1 + 0x249b, "simtower_vprinter_dispatch_words24");
        c.comment(NE1 + 0x249b, "SPRF02 adjacent48-byte data, not functions. All24 original targets equal supplier offsets+1ff2. Whole CODE1241 differs58 bytes: five WORD sites plus24 target WORDs; no normalized equality, final candidate link or complete formatting semantics.");
        int[] targets = { 0x20f9,0x20e3,0x212e,0x20ee,0x215c,0x2169,0x21a7,0x21ae,0x21b3,0x2117,0x21dc,0x21ba,0x21be,0x21c2,0x223c,0x22e9,0x228c,0x22ac,0x242d,0x2469,0x2469,0x2469,0x2109,0x210f };
        for (int i = 0; i < targets.length; i++) {
            offsetReference(c, NE1 + 0x249b + 2L * i, targets[i], NE1 + targets[i], "SPRF02 CS-relative dispatch WORD, not an unconditional call");
        }
        offsetReference(c, NE1 + 0x20de, 0x249b, NE1 + 0x249b, "SPRF02 stored CS-indexed table operand");
        originalWord(c, NE1 + 0x20cf, 0xb63);
        originalWord(c, NE1 + 0x22d9, 0xb5c);
        c.comment(NE1 + 0x20cf, "SPRF02 stored DATA0b63 = base0b5c+7; does not establish live DS loading.");
        c.comment(NE1 + 0x22d9, "SPRF02 stored NULL-fallback DATA0b5c; no live DS/valid-pointer claim.");
        nearCall(c, NE1, 0x222a, 0x3276, "SPRF02 supplier __LONGTOA candidate; subordinate body/effects unrecovered");
        nearCall(c, NE1, 0x2325, 0x3417, "SPRF02 supplier __REALCVT candidate; subordinate body/effects unrecovered");
        bytes(c, NE82 + 0xb5c, 7, "vprinter_null_text7");
        bytes(c, NE82 + 0xb63, 96, "vprinter_dispatch_indices96");
        c.comment(NE82 + 0xb5c, "SPRF02 complete DATA103 literally equals both inspected same-model members: (null)/NUL7 then96 dispatch-index bytes. Shared bytes do not identify a release. Stored operands qualify placement, not loaded DS or candidate linkage.");
    }

    private void exit(Context c) throws Exception {
        StructureDataType data = partial("ExitData14Partial", 14, "CRT03 complete initialized member contribution candidate NE82[1036,1044); six differing raw FAR-chain bytes, not whole DATA equality.");
        DataType far = farStorage(c);
        for (int i = 0; i < 3; i++) {
            data.replaceAtOffset(4 * i, far, 4, "callback_storage_" + i, "Actual native FAR binding to NE1:3e6a, not a function prototype.");
        }
        data.replaceAtOffset(12, WORD, 2, "guard_word", "Original helper tests/sets NE82:1042.");
        c.data(NE82 + 0x1036, resolve(c, data));
        String[] namesData = { "__exitbuf", "__exitfopen", "__exitopen" };
        for (int i = 0; i < 3; i++) {
            c.label(NE82 + 0x1036 + 4L * i, "simtower_crt45_candidate_" + namesData[i]);
            c.farReference(NE82 + 0x1036 + 4L * i, 1, 0x3e6a, NE1 + 0x3e6a);
        }
        importedFar(c, NE1 + 0x3e87, 5, 48, "CRT03 GETMODULEUSAGE candidate / KERNEL48; transitive servicing unproved");
        for (int[] field : new int[][] { {0x1a,0x3a}, {0x28,0x1042}, {0x2f,0x1042}, {0x37,0x1034}, {0x3b,0x1034}, {0x42,0xe6c8}, {0x46,0x1034}, {0x52,0x1036}, {0x6c,0x103a}, {0x70,0x103e} }) {
            storedData(c, NE1 + 0x3e6a + field[0], field[1], "CRT03 EXIT supplier binding");
        }
        for (int[] call : new int[][] { {0x3eb5,0xc9}, {0x3ebe,0xdc}, {0x3ec3,0xdb}, {0x3edf,0xdd} }) {
            converted(c, NE1, call[0], call[1], "CRT03 EXIT converted supplier call");
        }
    }

    private void exceptions(Context c) throws Exception {
        bytes(c, NE79 + 0x66, 42, "xxv_raw_table42");
        c.comment(NE79 + 0x66, "CRT03 xxv.cpp [0066,0090) raw table-like contribution, execution ownership unresolved; not a tenth function. Twenty-five member publics = nine code entries + fifteen DATA + one unplaced BSS, not25 code functions.");
        c.comment(NE79 + 0x2d7, "CRT03 initializer122 has28 raw unequal field bytes. Genuine startup source NE1:0007 binds here. Complete exception semantics, imported/transitive servicing and integral member linkage remain unproved.");
        StructureDataType data = partial("XxvInitialized296Partial", 296, "CRT03 full initialized DATA placement candidate NE82[07ec,0914), four raw differing FAR-chain bytes. Public labels do not establish public field extents/types.");
        DataType far = farStorage(c);
        data.replaceAtOffset(0xa, far, 4, "terminate_storage", "Actual native FAR binding to NE79:0000.");
        data.replaceAtOffset(0xe, far, 4, "unexpected_storage", "Actual native FAR binding to NE79:0143.");
        data.replaceAtOffset(0x12, WORD, 2, "terminate_ds_word", "Initializer operand034c stored07fe; no live DS claim.");
        data.replaceAtOffset(0x14, WORD, 2, "unexpected_ds_word", "Initializer operand0349 stored0800; no live DS claim.");
        c.data(NE82 + 0x7ec, resolve(c, data));
        int[] offsets = { 0,4,6,8,0xa,0xe,0x12,0x14,0x16,0x1a,0x1c,0x20,0x24,0x28,0xa8 };
        String[] namesData = { "CPPexceptionList", "exceptFlags", "savedDS", "savedSI", "terminatePTR", "unexpectdPTR", "terminate_DS", "unexpectd_DS", "throwFileName", "throwLineNumber", "throwExceptionName", "exceptStaticBuffP", "exceptMemAllocVars", "exceptionNameBuff", "ExceptStaticXbuff" };
        for (int i = 0; i < offsets.length; i++) {
            c.label(NE82 + 0x7ec + offsets[i], "simtower_crt45_candidate_" + namesData[i]);
        }
        c.comment(NE82 + 0x7ec, "CRT03 all15 DATA publics and intermediate bytes accounted; labels are supplier correspondence candidates, not field-size/prototype recovery. Four-byte BSS public __DestructorCountPtr has no selected-member fixup/reference and no established original placement; deliberately no arbitrary zero-slot label/data.");
        c.farReference(NE82 + 0x7f6, 79, 0, NE79);
        c.farReference(NE82 + 0x7fa, 79, 0x143, NE79 + 0x143);
        c.farReference(NE79 + 0x6a, 79, 0x129, NE79 + 0x129);
        c.farReference(NE79 + 0x88, 79, 0x66, NE79 + 0x66);
        for (int field : new int[] { 0x15,0x3d,0xae,0xd3,0xec,0x102,0x157,0x17f,0x1b3,0x1d3,0x1ec,0x202,0x2fc,0x311,0x32c }) {
            c.farReference(NE79 + field, 1, 0x1d4c, NE1 + 0x1d4c);
            c.comment(NE79 + field, "CRT03 supplier @__EH_GetClientData$qui candidate; native FAR binding NE1:1d4c, not its prototype or transitive effects.");
        }
        for (int[] field : new int[][] { {3,0x3e26}, {0x132,0x3e26}, {0x222,0x3e26}, {0xa8,0x259e}, {0x2ef,0x1a55}, {0x304,0x1e47} }) {
            c.farReference(NE79 + field[0], 1, field[1], NE1 + field[1]);
            c.comment(NE79 + field[0], "CRT03 native supplier dependency binding NE1:" + Integer.toHexString(field[1]) + "; abort/flushall/EH helper name candidates do not establish full effects or noreturn.");
        }
        for (int[] field : new int[][] { {0x2db,0x940}, {0x2e6,0xe6bc}, {0x2ea,0xe6be}, {0x2f5,0xe6be}, {0x2f8,0xe6bc}, {0x30a,0x944}, {0x30d,0x942} }) {
            storedData(c, NE79 + field[0], field[1], "CRT03 cachedSS/cachedVarPtr/EH_TablePtr supplier binding");
        }
        nativeInternal(c, NE79 + 0x9a, 2, 79, 0);
        nativeInternal(c, NE79 + 0x9d, 5, 79, 0x7e);
        c.comment(NE79 + 0x9a, "CRT03 native SEG relocation to NE79; separately retained from OFF16L009d. Not an invented flat pointer.");
        c.comment(NE79 + 0x9d, "CRT03 native OFF16L relocation to NE79:007e, within raw table contribution; not a code-entry declaration.");
        originalWord(c, NE79 + 0x349, 0x800);
        originalWord(c, NE79 + 0x34c, 0x7fe);
        c.comment(NE79 + 0x349, "CRT03 stored DATA0800 corresponds to supplier0014; placement evidence, not live DS resolution.");
        c.comment(NE79 + 0x34c, "CRT03 stored DATA07fe corresponds to supplier0012.");
        for (int[] call : new int[][] { {0x9f,0x3649}, {0x12c,0x1a58}, {0x139,0x36ba} }) {
            converted(c, NE79, call[0], call[1], "CRT03 XXV converted supplier call; transitive body/effects unproved");
        }
    }

    private void originalWord(Context c, long source, int expected) throws Exception {
        int actual = Byte.toUnsignedInt(c.original().getOriginalByte(source)) | Byte.toUnsignedInt(c.original().getOriginalByte(source + 1)) << 8;
        if (actual != expected) {
            throw new IllegalStateException(ID + " contradictory original WORD at FILE " + Long.toHexString(source));
        }
    }

    private void storedData(Context c, long source, int offset, String qualification) throws Exception {
        originalWord(c, source, offset);
        c.comment(source, qualification + "; stored NE82 offset" + Integer.toHexString(offset) + ". Stored placement correspondence only, not observed DS loading or a live resolved pointer.");
    }

    private void nativeInternal(Context c, long source, int type, int segment, int offset) {
        boolean found = c.program().getRelocationTable().getRelocations(c.mapped(source)).stream().anyMatch(r -> {
            long[] values = r.getValues();
            return r.getStatus() == Relocation.Status.APPLIED && r.getType() == type && values != null && values.length == 5 && values[1] == 0 && values[3] == segment && values[4] == offset;
        });
        if (!found) {
            throw new IllegalStateException(ID + " missing qualified native internal relocation at FILE " + Long.toHexString(source));
        }
    }

    private void offsetReference(Context c, long source, int storedOffset, long target, String qualification) throws Exception {
        originalWord(c, source, storedOffset);
        c.program().getReferenceManager().addMemoryReference(c.mapped(source), c.mapped(target), RefType.DATA, SourceType.ANALYSIS, 0);
        c.comment(source, qualification + "; stored WORD " + Integer.toHexString(storedOffset) + ", qualified original FILE target " + Long.toHexString(target) + ".");
    }

    private void nearCall(Context c, long base, int call, int target, String qualification) throws Exception {
        if (c.original().getOriginalByte(base + call) != (byte) 0xe8) {
            throw new IllegalStateException(ID + " missing qualified near CALL");
        }
        originalWord(c, base + call + 1, (target - call - 3) & 0xffff);
        c.comment(base + call, qualification + "; original near CALL target FILE " + Long.toHexString(base + target) + ". No stronger callee effects inferred.");
    }

    private void converted(Context c, long base, int start, int target, String qualification) throws Exception {
        if (c.original().getOriginalByte(base + start) != (byte) 0x90 || c.original().getOriginalByte(base + start + 1) != (byte) 0x0e) {
            throw new IllegalStateException(ID + " missing complete NOP/PUSH-CS conversion window");
        }
        nearCall(c, base, start + 2, target, qualification);
        c.comment(base + start, qualification + "; complete five-byte NOP/PUSH CS/near CALL window, not raw FAR-call equality or proof of actual candidate link. Caller effects beyond this stored relation unproved.");
    }

    private void importedFar(Context c, long source, int module, int ordinal, String qualification) {
        boolean found = false;
        for (Relocation relocation : c.program().getRelocationTable().getRelocations(c.mapped(source))) {
            long[] values = relocation.getValues();
            if (relocation.getStatus() == Relocation.Status.APPLIED && relocation.getType() == 3 && values != null && values.length == 5 && values[1] == 1 && values[3] == module && values[4] == ordinal) {
                found = true;
            }
        }
        if (!found) {
            throw new IllegalStateException(ID + " missing qualified native imported FAR relocation at FILE " + Long.toHexString(source));
        }
        c.comment(source, qualification + "; actual native applied NE import module" + module + " ordinal" + ordinal + ". Name is correspondence-qualified; no imported ABI, return value or servicing inferred.");
    }
}
