package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Exact retained TASM3.1 image facts, not historical application-tool attribution or an OMF model. */
public final class Tasm31Profile extends ToolchainProfile {
    public static final String ID = "tasm31-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/TASM31");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final long DATA_FILE = 0x18310;

    public Tasm31Profile() {
        super(ID, "Old-style DOS Executable (MZ)", 129266, "80534cd6a1e2c2b4376ae3f21954c6dbfa77a6998d5e0bf8b8bee6153f3174ea");
    }

    @Override
    public void apply(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        applyTypes(c);
        applyCall(c);
        applyReplay(c);
        applyExpressions(c);
        applyRecords(c);
        applyFlagHelpers(c);
        applyLiteralControls(c);
        applyMzReferences(c);
        log.appendMsg(ID, "Exact original-file TASM3.1 CALL, replay, expression, internal-record, returned-flag and literal-control facts applied. Current runtime state, external OMF identities and historical producer/settings remain unproved.");
    }

    private StructureDataType partial(String name, int length, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, length);
        type.setDescription(description + " Unknown bytes remain undefined. Descriptive partial analysis view, not historical source or a flat-pointer contract.");
        return type;
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void word(StructureDataType type, int offset, String name, String qualification) {
        type.replaceAtOffset(offset, WORD, 2, name, qualification);
    }

    private void byteField(StructureDataType type, int offset, String name, String qualification) {
        type.replaceAtOffset(offset, BYTE, 1, name, qualification);
    }

    private void applyTypes(Context c) {
        StructureDataType expression = partial("Expression40Partial", 40, "R133/R139/R145: clearing/copying20 words is40 bytes;48CC advances its allocation pool by THREE paragraphs, independently of this view size. Clearing and literal forward-copy geometry require DF=0, valid selected storage and noninterfering aliases.");
        byteField(expression, 0, "tag", "29 can be immediate FAR request; finalization can clear bit20 or transfer deferred29 as09.");
        byteField(expression, 1, "subtype", "Low three bits and independent upper bits are current numeric controls.");
        word(expression, 2, "tag_value", null);
        byteField(expression, 4, "flags04", "Current bit04 qualifies identity; bit80 changes CALL admission.");
        byteField(expression, 5, "flags05", "Finalizer priority10 before20;40 controls deferred transfer.");
        word(expression, 6, "pending_selector", "Raw selector/handle, not a resolved pointer.");
        word(expression, 0xa, "value_low", "Ordinary fresh FAR left storesFFFE here; IDEAL direct type29 instead leaves0A zero.");
        word(expression, 0xc, "value_high", null);
        word(expression, 0x10, "word10", "Fresh clear sets byte10=1; cached copy overwrites the whole word.");
        word(expression, 0x14, "word14", null);
        word(expression, 0x16, "word16", null);
        word(expression, 0x18, "target_identity", null);
        word(expression, 0x1a, "selected_identity", null);
        word(expression, 0x1c, "deferred_word", null);
        word(expression, 0x1e, "pending_word1e", null);
        word(expression, 0x20, "pending_word20", null);
        word(expression, 0x22, "pending_identity", null);
        byteField(expression, 0x24, "value_extension", null);
        byteField(expression, 0x25, "deferred_tag", "Transfer masks0F;95FB clears this byte and word1C, not pending06 or identity18.");
        word(expression, 0x26, "format_handle", "Selected94A4 format1 branch reads this raw handle.");
        resolve(c, expression);

        StructureDataType state = partial("SelectedState16Partial", 16, "R145: selected state consumed by4A75; scalar discriminator and cached-expression alternative are distinct.");
        word(state, 0, "key_low", null);
        word(state, 2, "key_selector", null);
        word(state, 4, "successor_selector", null);
        byteField(state, 8, "scalar_discriminator", null);
        byteField(state, 9, "scalar_extension", null);
        word(state, 0xa, "scalar_low_or_cached_selector", "Reread after allocation in cached-copy branch.");
        word(state, 0xc, "scalar_high", null);
        word(state, 0xe, "scalar_pending_selector", null);
        resolve(c, state);

        StructureDataType context = partial("ReplayContext40Partial", 40, "TI01:7050..7078 copied20 words. Does NOT include the callback at7078. Names refer to this context origin, not a live DS assertion.");
        word(context, 0, "endpoint_low", null);
        word(context, 2, "endpoint_high", null);
        word(context, 4, "source_word7054", null);
        word(context, 6, "position_low", null);
        word(context, 8, "position_high", null);
        word(context, 0xa, "source_word705a", null);
        word(context, 0xc, "source_word705c", null);
        byteField(context, 0xe, "control705e", null);
        byteField(context, 0xf, "control705f", null);
        word(context, 0x10, "current_identity7060", null);
        word(context, 0x14, "control7064", "Bit08 diagnostic is not guaranteed suppression of fill.");
        byteField(context, 0x27, "descriptor_index7077", null);
        DataType contextType = resolve(c, context);
        StructureDataType snapshot = partial("CallbackSnapshot48Partial", 48, "TI01:24-word7050→71B6 copy includes callback7078 at snapshot+28; post-callback current7056/7058 overwrite snapshot+0/+2. Not an immutable old-state snapshot.");
        snapshot.replaceAtOffset(0, contextType, 40, "copied_context", "First pair subsequently overwritten with current position.");
        word(snapshot, 0x28, "selected_near_callback", "Source7078; excluded from the full-record20-word transfer.");
        word(snapshot, 0x2a, "extension_size", null);
        word(snapshot, 0x2c, "extension_save_callback", "Snapshot71E2, current near address.");
        word(snapshot, 0x2e, "extension_restore_callback", "Snapshot71E4, current near address.");
        resolve(c, snapshot);

        StructureDataType compact = partial("CompactReplayRecord16Partial", 16, "TI01: one paragraph requested; record05 bit10 selects compact interpretation.");
        replayHeader(compact);
        word(compact, 6, "saved_source7054", null);
        word(compact, 8, "saved_position_low", null);
        word(compact, 0xa, "saved_position_high", null);
        word(compact, 0xc, "extent_word", "Added to saved position with ADD/ADC, not unrestricted signed length.");
        word(compact, 0xe, "saved_source705a", null);
        resolve(c, compact);
        StructureDataType full = partial("FullReplayRecord46Partial", 0x2e, "TI01: three paragraphs requested independently; bit10 clear restores record06..2E→7050..7078. Payload excludes7078 callback.");
        replayHeader(full);
        full.replaceAtOffset(6, contextType, 40, "saved_context", "06/08 are post-callback endpoint;0C/0E are pre-callback position under qualified copy.");
        DataType fullType = resolve(c, full);
        StructureDataType extended = partial("ExtendedReplayHeader50Partial", 0x32, "TI01: bit20 extension form; request paragraphs=u16(current707A+0041)>>4, not a fixed allocation or safe wrap guarantee; extension payload begins32.");
        extended.replaceAtOffset(0, fullType, 0x2e, "full_record", null);
        word(extended, 0x2e, "extension_size", null);
        word(extended, 0x30, "extension_near_callback", "Restore invokes with DI32 only when current record05 bit20 set.");
        resolve(c, extended);

        StructureDataType descriptor8 = partial("CallbackDescriptor8Partial", 8, "TI01 selector indexes current7077*8 into one of four initial tables; valid index extent remains conditional.");
        word(descriptor8, 0, "token_base_delta", "Adds current7618 before publishing761E.");
        word(descriptor8, 2, "word7620", null);
        word(descriptor8, 4, "word7622", null);
        word(descriptor8, 6, "word7624", null);
        resolve(c, descriptor8);
        StructureDataType descriptor4 = partial("CallbackDescriptor4Partial", 4, "TI01 mode-bit10 branch indexes7077*4 and publishes only761E/7620.");
        word(descriptor4, 0, "token_base_delta", null);
        word(descriptor4, 2, "word7620", null);
        resolve(c, descriptor4);

        StructureDataType record = partial("ClassTaggedRecord32Partial", 32, "R164/R176/R182:3E85 requests two paragraphs, links globally, clears only1C/1E and writes06/05. Constructors do NOT initialize08; no blanket zero-fill.");
        word(record, 0, "previous_selector", null);
        word(record, 2, "next_selector", "4AC7 saves current next before callback; not reread afterward.");
        byteField(record, 4, "record_class", "Selected0A/0C/0D, not external OMF types.");
        byteField(record, 5, "count_byte", null);
        word(record, 6, "source_handle", null);
        word(record, 8, "published_index", "Current callback result: class0A uses6F2E, classes0C/0D6F32; later consumer rereads current08.");
        word(record, 0xa, "link_or_class_word", "Class0A link walk freshly rereads0A after emission; class0C post-helper BP.");
        word(record, 0xc, "class0d_word0c", null);
        word(record, 0xe, "class0d_word0e", null);
        word(record, 0x10, "class0d_word10", null);
        word(record, 0x12, "class0d_word12", null);
        byteField(record, 0x14, "class0d_selector", "Selected fresh caller supplies zero; selector-one callback is code, not observed caller state.");
        word(record, 0x1c, "pending_block1c", null);
        word(record, 0x1e, "pending_block1e", null);
        resolve(c, record);
        StructureDataType queue = partial("InternalQueuePayload9", 9, "R152: ordered STOS stores at old block06, conditional on DF=0 and valid nonaliased storage; not an external OMF structure.");
        byteField(queue, 0, "internal_class", "Current CL.");
        word(queue, 1, "location_low", "Current BX.");
        word(queue, 3, "location_high", "Current DX.");
        word(queue, 5, "first_projection", "Current SI.");
        word(queue, 7, "second_projection", "Saved original DI popped into AX; save occurs after any preceding drain.");
        resolve(c, queue);
        StructureDataType selected = partial("InputControlRecord18Partial", 0x12, "R283:1615 execution-CS selected record; accepted constructor values do not freeze later current fields.");
        for (int offset = 0; offset < 0x12; offset += 2) {
            word(selected, offset, "word" + Integer.toHexString(offset), offset == 4 ? "Advertised object-code selection; consumer freshly loads this field into43D2." : null);
        }
        resolve(c, selected);
        EnumDataType classes = new EnumDataType(TYPES, "InternalRecordClass", 1);
        classes.add("linked_index_class0a", 0xa);
        classes.add("counted_class0c", 0xc);
        classes.add("payload_class0d", 0xd);
        resolve(c, classes);
        EnumDataType flags = new EnumDataType(TYPES, "ReplayRecord05Mask", 1);
        flags.add("compact_interpretation", 0x10);
        flags.add("extension_callback", 0x20);
        flags.setDescription("Independent masks; post3016 CX contributes to04/05, not an exclusive enumeration or observed historical record.");
        resolve(c, flags);
    }

    private void replayHeader(StructureDataType type) {
        word(type, 0, "next_selector", null);
        word(type, 2, "returned3016_word", null);
        word(type, 4, "current_control_word", "Current43D7 high flags maskedC000 combined with actual post3016 CX; byte05 contains masks10/20.");
    }

    private void code(Context c, int segment, int start, int end, String name, String qualification) throws Exception {
        long origin = 0x800L + 16L * segment;
        c.function(origin + start, origin + end, "tasm31_" + name, 0, "Logical " + Integer.toHexString(segment) + ":[" + Integer.toHexString(start) + "," + Integer.toHexString(end) + "). " + qualification);
    }

    private void words(Context c, long fileOffset, int count, String label) throws Exception {
        c.data(fileOffset, new ArrayDataType(WORD, count, 2));
        c.label(fileOffset, "tasm31_" + label);
    }

    private void reference(Context c, long source, long target) {
        c.program().getReferenceManager().addMemoryReference(c.mapped(source), c.mapped(target), RefType.DATA, SourceType.ANALYSIS, 0);
    }

    private void applyCall(Context c) throws Exception {
        code(c, 0, 0x6c4d, 0x6c8d, "encode_call", "R119/TI01: current tag29 and8C90 CF choose ordinary16-bit four-byte0E E8 or five-byte9A. Four-byte branch has NO NOP; later linker90 0E E8 rewrite is distinct. Three terminal tails to36D6; alternative indirect/operand-size descendants remain opaque.");
        code(c, 0, 0x8c90, 0x8d01, "call_far_predicate_cf", "R119/R145: CF1 retains FAR. Requires current SMART705E:20, zero operand06 and qualified identity. Ordinary branch installs postlookup AX as ES (including0), reads1A BEFORE04, then restores operand ES/CX; not simply7060 equality. IDEAL branch normalizes target first/current second. No numeric AX-bool contract.");
        code(c, 0, 0x7caa, 0x7ce9, "emit_near_operand", "R152/TI01: ordinary16-bit branch includes already emitted prefix count in displacement, prepares current operand, emits CL then word.8DF7 CF1 alternate width is separate; opaque helpers are not assumed to preserve arbitrary registers.");
        code(c, 0, 0x7ce9, 0x7d0a, "emit_far_operand", "R119/TI01: ordinary16-bit branch emits CL9A plus low offset/word16; alternative-width branch is not generalized. Terminal tail910F, not inline data.");
        code(c, 0, 0x40f6, 0x4113, "emit_byte", "TI01: writes AL at6F4E+old6F4C, increments word count, ancillary425E conditional. Adjacent4113 literal90 is NOT part of body or NOP-fill owner.");
        code(c, 0, 0x4114, 0x412f, "emit_word", "TI01: current AX write/count+2; tails425E. Adjacent412F excluded.");
        code(c, 0, 0x4130, 0x414f, "emit_word_pair", "TI01: current AX/CX write/count+4; tails425E. No flat pointer prototype.");
        code(c, 0, 0x7e82, 0x7e94, "prepare_call_operand", "R133: save operand ES to7406, reset emission, explicitly save CX around9698. Materialization effects remain conditional.");
        code(c, 0, 0x7f4b, 0x7f6e, "classify_immediate_cf", "R139 corrected complete end includes failure RET7F6D. Tags28/29 accepted CF0; tag20 has additional current mode/word14 tests.");
        words(c, DATA_FILE + 0x2724, 554, "token_dispatch_words554");
        c.comment(DATA_FILE + 0x2724, "R119/TI01: initial DS-relative near dispatch table,554 words. Selected current token minus7618 is range-checked before indirect dispatch; raw entries are not unconditional calls or554 proved complete functions. Initialized-data projection18310+DS is conditional on the startup-selected segment, not every live DS.");
        reference(c, DATA_FILE + 0x27ba, 0x800 + 0xcf05);
        c.label(DATA_FILE + 0x27ba, "tasm31_call_dispatch_slot");
        c.comment(0x800 + 0xcf05, "R119: selected ordinary ingressCF1C directly calls6C4D then tailsF5DC;CF05..CF2D is a selected partition with external alternatives, not a proven complete encompassing function.");
        c.data(0x1b310, new ArrayDataType(BYTE, 5, 1));
        c.label(0x1b310, "tasm31_call_pascal_token");
        c.comment(0x1b310, "R119:04 CALL, zero-based token75 among554 registered length-prefixed names. Successful token registration/actual parser state required; spelling alone does not prove traversal.");
    }

    private void applyReplay(Context c) throws Exception {
        code(c, 0, 0x45b3, 0x461e, "restore_replay_record", "TI01: record05:10 compact restores selected fields/endpoint; otherwise forward20-word06..2E→7050..7078 requires DF0 and valid DS/SS. Regenerates7078 callback after restore;05:20 invokes near record30 with DI32. Current ES/DS changes are real.");
        code(c, 0, 0x46f5, 0x4715, "snapshot_and_dispatch", "TI01: forward24-word7050..7080→71B6..71E6 includes7078 at71DE; indirect CALL[7078]. AFTER callback freshly rereads7056/7058 to overwrite71B6/71B8; no arbitrary callback/global/record-ES preservation.");
        code(c, 0, 0x4715, 0x4793, "admit_replay_record", "TI01:47F2 returned CF selects compact/full. One paragraph compact; three paragraphs full with20-word snapshot copy ending before71DE; extension size derives from current707A, stores2E/30 and invokes snapshot71E2 with DI32. Valid finite allocation/DF/aliases remain conditions.");
        code(c, 0, 0x4793, 0x47f2, "allocate_link_replay_record", "TI01: paragraph pool71EA/71EC, save record ES around3016, store actual returned AX at02;04 uses current43D7 plus POST3016 CX. LES/XCHG list insertion stores replaced selector at00. Allocator descendants opaque.");
        code(c, 0, 0x47f2, 0x4822, "compact_replay_predicate_cf", "TI01: rejects extension71E4, missing prior71F2 or14-word current context mismatch; SUB/SBB endpoint difference returns CF, not only numeric low difference. REPE comparison geometry requires DF0/valid storage.");
        code(c, 0xf90, 0x66d2, 0x675a, "select_replay_callback", "TI01: current705F:10 selects F3A9 versusF50D into7078. Clear branch indexes current7077*8 into selected2BC8/2C68/2B78/2C18; set branch indexes2CB8 by*4. Valid table/state extent conditional; selection is not historical pass attribution.");
        c.label(0x800 + 0xf3a9, "tasm31_callback_f3a9_prefix");
        c.label(0x800 + 0xf50d, "tasm31_callback_f50d_prefix");
        c.comment(0x800 + 0xf3a9, "TI01: selected callback/dispatch partition, not a proved complete single function. F419..F431 token range check/indirect dispatch; descendants opaque. F50D has corresponding F535..F540 branch.");
        for (int offset : new int[] { 0x2b78, 0x2bc8, 0x2c18, 0x2c68, 0x2cb8 }) {
            String type = offset == 0x2cb8 ? "CallbackDescriptor4Partial" : "CallbackDescriptor8Partial";
            c.data(DATA_FILE + offset, c.program().getDataTypeManager().getDataType(TYPES, type));
            c.label(DATA_FILE + offset, "tasm31_initial_descriptor_" + Integer.toHexString(offset));
            c.comment(DATA_FILE + offset, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride.");
        }
        c.data(DATA_FILE + 0x7050, c.program().getDataTypeManager().getDataType(TYPES, "ReplayContext40Partial"));
        c.data(DATA_FILE + 0x71b6, c.program().getDataTypeManager().getDataType(TYPES, "CallbackSnapshot48Partial"));
        c.label(DATA_FILE + 0x7050, "tasm31_initial_replay_context_storage");
        c.label(DATA_FILE + 0x71b6, "tasm31_initial_snapshot_storage");
        words(c, DATA_FILE + 0x7078, 1, "initial_selected_callback_storage");
        c.comment(DATA_FILE + 0x7050, "TI01: qualified initialized-data storage projection18310+offset only; startup DS/SS agree after relocation-backed setup, not all later runtime segments. Dynamic allocated replay records are NOT placed at fixed file addresses.20-word full record excludes7078;48-byte temporary snapshot includes it.");
        c.comment(0x800 + 0x4704, "TI01 actual indirect CALL[7078]. Selected targetsF3A9/F50D depend on current state; no unconditional call references fabricated from zero initial storage.");
    }

    private void applyExpressions(Context c) throws Exception {
        code(c, 0, 0x4b89, 0x4bdf, "finalize_expression", "R139:05 bit10 has priority; save POST5989 word04 across95FB. Bit20-only calls6311 then FRESH word04. After4BED read CURRENT05:40, transfer current25&0F→tag and1C→02. Deferred29 becomes09, not an unconditional FAR encoder request.");
        code(c, 0, 0x4bed, 0x4bfc, "materialize_expression", "R139:5F26→9698,600F,6096,4BFC then tail5F2D reloads CURRENT global7406 as ES. Not arbitrary record/global preservation.");
        code(c, 0, 0x4bfc, 0x4c2c, "mask_materialized_tag", "R139:clear tag20,set04:80; conditional04:08 and05 nibble updates. Immediate29 can become09 independently of deferred transfer.");
        code(c, 0, 0x5989, 0x59eb, "save_tag_or_resolve_identity", "R139:tag20 saves00/02→25/1C then clears tag/value and pending fields;4B89 immediately95FB discards this temporary saved tag. Other branch stores actual returned170A CX to18. Descendant effects qualified.");
        code(c, 0, 0x95fb, 0x960c, "clear_deferred_tag", "R133/R139:clear05:40,25,1C only; not pending06 or identity18.");
        code(c, 0, 0x6311, 0x6361, "transfer_pending_identity", "R139:copy1E/20→14/16 before tag test; only nonzero22 updates18 and conditionally1A/current subtype/04:04. Does not directly write pending06; not transitive preservation.");
        code(c, 0, 0x1a48, 0x1a51, "lookup_expression", "R145:1C65 selects state in ES, tail4A75 with DI08; sometimes AX0 while ES remains selected state. No unconditional pointer-return prototype.");
        code(c, 0, 0x1c65, 0x1ce7, "select_symbol_state", "R145:current43D6/cache0E selects state; strictJA successor choice versus initialJAE, conditional cache write. Valid terminating links/finite arithmetic required; returned ES need not equal AX.");
        code(c, 0, 0x4a75, 0x4ac6, "reconstruct_selected_expression", "R145:nonzero state08→fresh scalar;else nonzero0A→fresh cached40-byte copy after REREADING0A postallocation;else AX0 leaves ES selected. Qualified normal returns CF0/ZF1, not constant AX or safe null-record. DF0/valid storage/aliases conditional.");
        AddressSet allocation = c.range(0x50cc, 0x50e2);
        allocation.add(c.range(0x50f2, 0x511a));
        c.function(0x50cc, allocation, "tasm31_allocate_expression_view", 0, "R145 qualified allocation body FILE[50cc,50e2)+[50f2,511a), logical0:[48cc,48e2)+[48f2,491a). THREE-paragraph pool allocation is independent of the40-byte clear/copy. Ordinary fallthrough48de→48e2 reaches the separately called clear entry; final4918 backedge reaches48d3. No exclusive ownership of that shared routine. Nonlocal exhaustion and opaque allocator descendants are not normal returns.");
        code(c, 0, 0x48e2, 0x48f2, "clear_expression_view", "R145 shared clear entry: genuine near CALL at logical0:5137/FILE5937 targets48e2/FILE50e2, independently of allocation entry48cc. XORAX/MOVDIAX/MOVCX14h/REPSTOSW clear40 bytes then set byte10=1; DF=0, valid selected ES storage and aliases remain conditions. This clear size is not the THREE-paragraph pool allocation.");
        c.label(0x5937, "tasm31_expression_clear_near_call");
        c.comment(0x5937, "Original E8a8f7 near CALL targets shared clear entry logical0:48e2/FILE50e2, not allocation entry48cc. No runtime execution or allocator success inferred.");
        code(c, 0, 0x950c, 0x952e, "map_type_word_to_al", "R133:negative branch complements ALL16 AX bits;FFFE→0001→table09. Only AL replaced, AH not zero-extended. OR20 by caller forms29.");
        c.data(0x1a20c, new ArrayDataType(BYTE, 3, 1));
        c.label(0x1a20c, "tasm31_negative_type_map_08_09_01");
        words(c, 0x1a21e, 1, "ordinary_far_type_fffe");
        c.comment(0x1a21e, "R133:fresh ordinary FAR numeric left word0A=FFFE under accepted initialization/class00 and DF0 clear. IDEAL direct left tag29/zero0A is different. PTR may defer29 at25 or set tag29 immediately; finalizer/encoder still consume actual current fields.");
    }

    private void applyRecords(Context c) throws Exception {
        code(c, 0, 0x1adc, 0x1b02, "project_current_handle", "R152:current handle07 bit20 clear returns word0E on ALL masked-class alternatives;bit20 set returns10. Numeric projections, not formal external IDs.");
        code(c, 0xf90, 0x3bb2, 0x3c65, "append_internal_queue9", "R152:normal existing-block route publishes updated06 before nine ordered stores CL,BX,DX,SI,saved DI. New-block route uses POST3F38 returnedAX/DL/DI, internal type06. DF0/valid nonaliased storage and ordinary stack required; alternate3B48/drain/allocators opaque.");
        code(c, 0xf90, 0x3588, 0x359b, "construct_class0a", "R182:after3E85 set class0A,zero0A,return currentES inAX;08 NOT initialized.");
        code(c, 0xf90, 0x35dd, 0x35ee, "construct_class0c", "R164:after3E85 set class0C,posthelperBP→0A,return currentES inAX;08 NOT initialized.");
        code(c, 0xf90, 0x35ee, 0x3618, "construct_class0d", "R176:class0D;posthelperBP/BX/DX/SI/DI→0A/0C/0E/10/12,CH→14. Fresh selected caller givesCH0, not selector-one observation;08 NOT initialized.");
        code(c, 0xf90, 0x3e85, 0x3ecd, "link_class_record", "R164:two-paragraph request, global linking precedes06/05 stores;clears only1C/1E. Explicit saves restore AX/CX, not blanket zero-fill or arbitrary descendant preservation.");
        code(c, 0xf90, 0x4ac7, 0x4ae5, "walk_class_callback_bx", "R164:save CURRENT record02 before class04 comparison and conditional CALL BX;restore saved next plus AX/BX. Valid acyclic list/normal returns required, not reread-next semantics.");
        code(c, 0xf90, 0x466f, 0x469d, "publish_class0a_index", "R182:5107 fresh current6F2E return→record08 BEFORE link walk. Current linked0A reread AFTER512F; terminal5142, not arbitrary originalES restoration.");
        code(c, 0xf90, 0x469d, 0x46cf, "publish_class0d_index", "R176:current14 normalized0/1,read current0C/0E/10/12;524B actual fresh current6F32 return→08. Not class0C payload semantics.");
        code(c, 0xf90, 0x4703, 0x472d, "publish_class0c_index", "R164:current06/05→5201,restore recordES,actual fresh current6F32 return→08 before optional tail. Counter wrap allowed;no universal first-index-one.");
        code(c, 0xf90, 0x4a96, 0x4ac7, "consume_current_class_index", "R157/R164:current queued handle08 and04 supply numeric method table then5446. Class0A→01,0C/0D→02;not formal LOCAT/FIXDAT or captured historical queue association.");
        c.data(0x19fc4, new ArrayDataType(BYTE, 14, 1));
        c.label(0x19fc4, "tasm31_internal_class_method14");
        c.comment(0x19fc4, "R164/R176/R182:literal method map00x10,01,00,02,02;internal class0A/0C/0D domain. Not serialized record tags or a complete external OMF schema.");
    }

    private void applyFlagHelpers(Context c) throws Exception {
        code(c, 0, 0x8c61, 0x8c90, "push_sign_extension_cf", "RF08:call-free;06 zero,04:04 clear,CBW low byte requires AH=current0B. Current705E:04 additionally requires CWD DX=current0C. CF0 admits sign extension, CF1 rejects;not a numeric bool, source-type or actual historical operand trace.");
        code(c, 0, 0xf606, 0xf645, "padding_gate_zf", "TI04/R207:consumeF687 ZF;fresh70AB:80/706C tests. Six work descendants274E,F827,2283,F6BA,22A9,23DD opaque;explicit XOR/DEC givesALFF/ZF0,other routeAL0/ZF1,AH not guaranteed. Saves BX/CX/DX on work route,not SI/ES/DS purity.");
        code(c, 0, 0xf687, 0xf6ba, "current_state_predicate_zf", "TI04:after optional074B, F69A FRESH70AF compare defines normal ZF1 exactly when that byte0;later current tests/explicit XOR DEC giveZF0. AL is not constant on direct returns;leaf flags do not define final predicate.");
        code(c, 0xf90, 0x074b, 0x0758, "conditional_store_leaf", "TI04:call-free43C3:80 test;clear writes4598=1,otherwise none. Does not supply finalF687 flags;validDS/stack and noninterfering storage required.");
        code(c, 0, 0x461e, 0x4694, "conditional_nop_fill", "TI01/R193/R199:SUB/SBB saved endpoint-current position;borrow has separate correction path. Nonborrow lowAX0 returns even ifDX nonzero.43C4 nonzero/43D6:08 clear adjusts record then BYPASSES7064 gate. Other route PUSHAX/CALLF606/POPAX consumes ZF,not AX.7064:08 diagnostic may return and fall through;465F uses THEN-CURRENT AX.4665 reloadsAL90 each iteration,emits into fresh buffer,then36D6. Conditional trailing90 is NOT linker's leading90 rewrite or proof of a historical CALL instance.");
        code(c, 0, 0x4694, 0x46b2, "correct_replay_record", "TI01:sets43DC=FF;05:10 chooses SUB record0C,AX else SUB06,AX/SBB08,DX. Does not changeAX/DX;not blanket signed subtraction or shrink-success return.");
        c.comment(0x800 + 0x464a, "TI04: PUSH AX;CALLF606;POP AX;JNE4670 restores residualAX WITHOUT changing returnedZF. Later diagnostic can still change currentAX;no pure AX-bool prototype applied.");
        c.comment(0x800 + 0x4665, "TI01 literal NOP supplier MOV AL,90 within461E..4694;reload every loop. Positive route reaches LOOP even for currentCX0, yielding65536 iterations under stable ordinary state;not unrestricted safe padding length.");
    }

    private void applyLiteralControls(Context c) throws Exception {
        c.data(0x17faf, new ArrayDataType(BYTE, 78, 1));
        c.label(0x17faf, "tasm31_cs1615_option_dispatch_table");
        c.comment(0x17faf, "R283:CS1615 header/default16AD,count25,three-byte rows. This is DATA,not25 complete functions;row13 FILE17FD9 is6F→17D9. Execution-CS1615 qualified by FAR target plusCS-relative table,not linear0F90 coordinate arithmetic.");
        reference(c, 0x17fda, 0x18129);
        c.label(0x18129, "tasm31_cs1615_object_control_writer");
        c.comment(0x18129, "R283:1615:17D9 literal suffix p/i/s maps2/3/0 with saved AX across1596;other branch selects1. FILE18152 LES DI,[433A] reloads pointer AFTER helpers,18156 writes selected current record+4. Advertised /os,/o,/op,/oi are standard/standard with overlays/Phar Lap/IBM. Not automatic settings,external format proof or historical compiler classification.");
        c.comment(0x16aba, "R283:execution1615:016A,not0F90:69BA execution claim. FRESH selectedES:[DI+4]→DS43D2;record02/06/08 independently supply current controls. Constructor default0 is not immutable or an observed invocation. DS43D2==1 retains subtype10 at94A4;other current values maskEF.");
        c.label(0x172ab, "tasm31_case_sensitivity_help_literal");
        c.comment(0x172ab, "Literal same-image help advertises /ml all,/mx globals,/mu none case sensitivity. Frozen source production used /ml /l;source/control observations are annotations only,no tool execution,historical setting or universal token-policy inference.");
        c.label(0x1739d, "tasm31_object_code_help_literal");
        c.comment(0x1739d, "R283/R287:literal /os,/o,/op,/oi help. One retained unchanged-source /o assembly produced OFF16L at0073 while preserving all180 CODE bytes/all other fields;no captured internal state,whole-OMF equality or historical producer claim. Profile does not configure or execute TASM.");
        c.comment(0x11bee, "Qualified entry0F90:1AEE setsCLD and relocatedDS/SS from17B1;initial data projection18310+offset is conditional on this segment. HeaderSS:SP1F32:0400 differs. Native MZ load paragraph is supplied by loader,not literal logical selectors; later1615 execution-CS is distinct.");
    }

    private void applyMzReferences(Context c) throws Exception {
        // Original offset words followed by segment words that the native MZ loader relocated.
        mzReference(c, 0x4dec, 0, 0x45ee, 0xf90, 0x66d2, 0x167d2);
        mzReference(c, 0x4e05, 0, 0x4607, 0xf90, 0x66d2, 0x167d2);
        mzReference(c, 0x4ee4, 0, 0x46e6, 0xf90, 0x66d2, 0x167d2);
        mzReference(c, 0xfe96, 0, 0xf698, 0xf90, 0x074b, 0x1084b);
        mzReference(c, 0xfeb1, 0, 0xf6b3, 0xf90, 0x074b, 0x1084b);
        mzReference(c, 0x11ce0, 0xf90, 0x1be2, 0x1615, 0x0c9f, 0x175ef);
    }

    /** Qualifies the selected pair against native MzLoader metadata, not a second relocation parser. */
    private void mzReference(Context c, long sourceFile, int sourceSegment, int sourceOffset, int targetSegment, int targetOffset, long targetFile) throws Exception {
        var source = c.mapped(sourceFile);
        var segmentField = c.mapped(sourceFile + 2);
        var target = c.mapped(targetFile);
        int originalOffset = Byte.toUnsignedInt(c.original().getOriginalByte(sourceFile)) | Byte.toUnsignedInt(c.original().getOriginalByte(sourceFile + 1)) << 8;
        int originalSegment = Byte.toUnsignedInt(c.original().getOriginalByte(sourceFile + 2)) | Byte.toUnsignedInt(c.original().getOriginalByte(sourceFile + 3)) << 8;
        if (originalOffset != targetOffset || originalSegment != targetSegment || sourceFile + 2 != 0x800L + 16L * sourceSegment + sourceOffset) {
            throw new IllegalStateException(ID + " contradictory original FAR pair at FILE " + Long.toHexString(sourceFile));
        }
        int loadedSegment = Short.toUnsignedInt(c.program().getMemory().getShort(segmentField));
        boolean qualified = c.program().getRelocationTable().getRelocations(segmentField).stream().anyMatch(r -> {
            long[] values = r.getValues();
            return r.getStatus() == Relocation.Status.APPLIED && r.getType() == 0 && values != null && values.length == 3 && values[0] == sourceSegment && values[1] == sourceOffset && values[2] == loadedSegment;
        });
        int loadedOffset = Short.toUnsignedInt(c.program().getMemory().getShort(source));
        if (!qualified || loadedOffset != targetOffset || !((SegmentedAddressSpace) target.getAddressSpace()).getAddress(loadedSegment, loadedOffset).equals(target)) {
            throw new IllegalStateException(ID + " missing native MZ relocation/file-target join at " + source);
        }
        reference(c, sourceFile, targetFile);
        c.comment(sourceFile, "Qualified native MZ relocated FAR pair → logical " + Integer.toHexString(targetSegment) + ":" + Integer.toHexString(targetOffset) + ", original FILE " + Long.toHexString(targetFile) + ". DATA relationship complements the decoded instruction; original paragraphs are not literal imported addresses.");
    }

}
