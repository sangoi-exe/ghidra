package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.util.task.TaskMonitor;

/** Facts for the supplied BC45/BIN/BCC.EXE;1 only; no historical application attribution. */
public final class Bcc45Profile extends ToolchainProfile {
    public static final String ID = "bcc45-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/BCC45");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    // Original-byte equality reread from the B4501 and SM07 source-qualified images.
    public Bcc45Profile() {
        super(ID, "New Executable (NE)", 768026, "6e58346640ca94e32b547c4df872d06905e58c5ef6d473d0b6a6a3903d640a46");
    }

    // BI01 installed-cells-and-branch-tables.txt: NE ordinal, offset, absolute original FILE.
    private static final int[][] ASM_CALLBACKS = {
        { 62, 0x09bb, 0xa75bb },
        { 56, 0x1237, 0x99637 },
        { 56, 0x11a9, 0x995a9 },
        { 56, 0x0fe4, 0x993e4 },
        { 56, 0x1123, 0x99523 },
        { 56, 0x11d1, 0x995d1 },
        { 56, 0x13f1, 0x997f1 },
        { 56, 0x14c0, 0x998c0 },
        { 62, 0x06aa, 0xa72aa },
        { 56, 0x15de, 0x999de },
        { 62, 0x0c45, 0xa7845 },
        { 62, 0x008c, 0xa6c8c },
        { 62, 0x009a, 0xa6c9a },
        { 62, 0x08c4, 0xa74c4 },
        { 56, 0x13d9, 0x997d9 },
        { 62, 0x00b7, 0xa6cb7 },
        { 62, 0x00ca, 0xa6cca },
        { 56, 0x15b5, 0x999b5 },
        { 56, 0x1580, 0x99980 },
        { 62, 0x0841, 0xa7441 },
        { 62, 0x096d, 0xa756d },
        { 62, 0x0886, 0xa7486 },
        { 62, 0x09a0, 0xa75a0 },
        { 62, 0x00e3, 0xa6ce3 },
        { 62, 0x10c2, 0xa7cc2 },
        { 62, 0x0220, 0xa6e20 }
    };
    private static final int[][] OBJ_CALLBACKS = {
        { 59, 0x1344, 0xa1b44 },
        { 60, 0x078c, 0xa318c },
        { 60, 0x060d, 0xa300d },
        { 60, 0x0207, 0xa2c07 },
        { 60, 0x05a0, 0xa2fa0 },
        { 60, 0x0673, 0xa3073 },
        { 60, 0x07f2, 0xa31f2 },
        { 60, 0x08b7, 0xa32b7 },
        { 59, 0x13c7, 0xa1bc7 },
        { 60, 0x0301, 0xa2d01 },
        { 63, 0x07dd, 0xa95dd },
        { 56, 0x018c, 0x9858c },
        { 56, 0x01b3, 0x985b3 },
        { 63, 0x06e1, 0xa94e1 },
        { 59, 0x17ae, 0xa1fae },
        { 63, 0x02d4, 0xa90d4 },
        { 63, 0x02e7, 0xa90e7 },
        { 60, 0x07c9, 0xa31c9 },
        { 56, 0x01f4, 0x985f4 },
        { 63, 0x0693, 0xa9493 },
        { 63, 0x0787, 0xa9587 },
        { 63, 0x06c0, 0xa94c0 },
        { 63, 0x0747, 0xa9547 },
        { 63, 0x0319, 0xa9119 },
        { 63, 0x00b1, 0xa8eb1 },
        { 63, 0x0433, 0xa9233 }
    };

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        DataType far = farRecord(c);
        applyBackends(c, far);
        applyRecordDomains(c, far);
        applyPseudoregisters(c, far);
        applyControlState(c);
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        c.function(0xa700b, 0xa7121, "bcc45_install_asm_callbacks", 4, "BI01 NE62:[040b,0521), selected forward-copy installer; no CLD in this body. ASM suffix/header requests are conditional.");
        c.function(0xa9412, 0xa9493, "bcc45_install_obj_callbacks", 4, "BI01 NE63:[0612,0693), selected forward-copy installer; no CLD in this body.");
        c.function(0xa7845, 0xa7c50, "bcc45_asm_instruction_serializer", 2, "BI01 NE62:[0c45,1050), instruction-tag consumer; operand formatting and output requests remain conditional.");
        c.function(0xa95dd, 0xa9f3c, "bcc45_obj_instruction_serializer", 2, "BI01 NE63:[07dd,113c), instruction-tag consumer; fixup queues and physical output remain distinct.");
        c.function(0xa7e8b, 0xa7ea9, "bcc45_asm_width_selector", 2, "BI01/RF02 NE62:[128b,12a9); descriptor-selected width is not a node category or backend-record tag.");
        c.function(0xa7ea9, 0xa82e1, "bcc45_asm_operand_formatter", 4, "BI01/RF02 NE62:[12a9,16e1); selected kind1 and offset-prefix paths only, no whole-operand semantic claim.");
        c.function(0xa6cca, 0xa6ce3, "bcc45_asm_branch_wrapper", 6, "RF04 NE62:[00ca,00e3), forwards three frame WORDs to NE56:0207; current9966 alternative, not instruction994e.");
        c.function(0xa90e7, 0xa9100, "bcc45_obj_branch_wrapper", 6, "RF04 NE63:[02e7,0300), forwards three frame WORDs to NE56:0207; current9966 alternative.");
        c.function(0x98441, 0x9849d, "bcc45_allocate_section_piece28", 0, "RF04 NE56:[0041,009d);001c allocation records section/text positions; allocator effects remain opaque.");
        c.function(0x9849d, 0x984df, "bcc45_close_section_piece", 0, "RF04 NE56:[009d,00df); final extent is distinct from branch reservation.");
        c.function(0x98532, 0x9858c, "bcc45_queue_fixup8", 6, "BI01 NE56:[0132,018c); writes position+0, incoming DWORD+2, class+6 and increments current piece count.");
        c.function(0x98607, 0x986cd, "bcc45_construct_branch_piece", 6, "RF04 NE56:[0207,02cd); BP+a code, BP+8 target, BP+6 short control. Reservation2/3/4/5 differs from final extent; signed1974 gate. No stronger parameter/storage prototype inferred.");
        c.function(0x894a3, 0x89521, "bcc45_allocate_control_arenas16", 0, "RF04 NE48:[0aa3,0b21); independently allocates and zero-fills three16-byte contributions via9b0a/9b12/9b1a, saves each result separately. First-offset writes across arenas do not establish equal-offset validity.");
        c.function(0xae33a, 0xae436, "bcc45_construct_parallel_backend_record", 8, "RF02/NR03 NE65:[0f3a,1036);1036 is exclusive end, never the entry. Five chronological two-byte allocations under9b2a/32/3a/42/4a; first returned storage offset used for writes, outward AX is old9a99 then incremented. Equality of storage offsets/counter/index and runtime survival are unproved.");
        c.function(0x67360, 0x67389, "bcc45_current_symbol_selector", 4, "RF02 NE32:[0f60,0f89); class9 redirects through symbol FAR0, class7 reads current WORD16. Not cached node WORD10.");
        c.function(0x5cefb, 0x5cf65, "bcc45_construct_symbol_reference_node", 14, "RF02 NE27:[04fb,0565); allocation remains opaque; selected tag/type/symbol/selector/flags writes only.");
        c.function(0x88a4d, 0x88ae1, "bcc45_lookup_register_spelling", 4, "RF02 NE48:[004d,00e1); selector/type lookup in seven-byte table, characters1..3 for type0a (two otherwise), conditional case conversion into current96e6..96e9. Not an unconditional EAX ABI.");
        c.function(0x6d6b5, 0x6d6cc, "bcc45_option_byte_store", 6, "BI02 NE36:[08b5,08cc); handler-specific row BYTE6 -> current DS:[row WORD4], returns AX1 without suffix validation.");
        c.function(0x6d436, 0x6d4a9, "bcc45_boolean_option_handler", 6, "BI02/RF03 NE36:[0636,06a9); current row/input/snapshot state and signed threshold acceptance are conditions.");
        c.function(0x94200, 0x9423d, "bcc45_frame_needed_predicate", 0, "BI04/RF03 NE54:[0000,003d); independent current WORD9a7c/9a80, BYTE9a15, BYTE9a0c&4, BYTE1997, or nonzero199a with9a91&1. Clearing1997 alone does not universally remove frames;1a0f has separate setup/DS-save/alignment consumers.");
        c.function(0x895f1, 0x8968e, "bcc45_capture_function_policy", 26, "RF03 NE48:[0bf1,0c8e), RETF1ah. Post-helper ordered state writes: zero-extend incoming BYTE[BP+10] into WORD9a91, then clear0200; separately clear register-use WORD9a9b at0c68. No9a9b-to9a91 assignment. Callback/current-segment/lifetime joins remain conditional.");
        c.function(0x9430e, 0x94491, "bcc45_windows_frame_builder", 0, "BI04/RF03 NE54:[010e,0291); selected BYTE9a9c masks01/02 request SI/DI saves after real helper/current-state tests. Register-use WORD9a9b gets1<<selector from actual selector lookup;8/9 can set these high-byte bits. No historical function save-state or physical emission inferred.");
        c.function(0xad705, 0xadb49, "bcc45_normalize_instruction_workspace", 2, "ZF01 NE65:[0305,0749). Selected009c CMP arm requires current A64c kind1, A659 kind4 and A65e DWORD0; transforms tag009c to005e OR, source kind1, destination selector copied to source. This arm tests neither1000 nor prior arithmetic flags. Cache invalidation, operand/request identity, current994e callback and physical output remain unproved.");
        log.appendMsg(ID, "Qualified backend tables, separate record domains, pseudoregisters and control/normalizer facts applied; dynamic state and historical producer identity remain unproved.");
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private StructureDataType partial(String name, int length, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, length);
        type.setDescription(description + " Unknown bytes remain undefined; descriptive analysis layout, not a recovered historical C type.");
        return type;
    }

    private DataType farRecord(Context c) {
        StructureDataType type = partial("FarStorage16", 4, "Offset and selector words; not a flat pointer or selector-resolution assertion.");
        type.replaceAtOffset(0, WORD, 2, "offset", null);
        type.replaceAtOffset(2, WORD, 2, "selector", null);
        return resolve(c, type);
    }

    private void applyBackends(Context c, DataType far) throws Exception {
        for (int family = 0; family < 2; family++) {
            long start = family == 0 ? 0x16fb2 : 0x1751c;
            int[][] callbacks = family == 0 ? ASM_CALLBACKS : OBJ_CALLBACKS;
            c.data(start, new ArrayDataType(far, 26, 4));
            c.label(start, family == 0 ? "bcc45_asm_source_callbacks26" : "bcc45_obj_source_callbacks26");
            c.comment(start, "BI01: 26 singleton nonadditive native NE FAR relocations. Conditional REP MOVSW installation to current DS:[9926,998e), CX=0034 requires DF=0, valid current segments and preservation. Displacement28h -> current994e instruction serializer; displacement40h -> current9966 branch wrapper. These source-table DATA references are not unconditional calls or proof of installed runtime state.");
            for (int i = 0; i < callbacks.length; i++) {
                int[] target = callbacks[i];
                c.farReference(start + 4L * i, target[0], target[1], target[2]);
            }
        }
        c.farReference(0xa6cd9, 56, 0x0207, 0x98607);
        c.farReference(0xa90f6, 56, 0x0207, 0x98607);
        words(c, 0xa7c50, 0xa7cc2, "bcc45_asm_callback_switch_words");
        words(c, 0xa9f3c, 0xaa146, "bcc45_obj_callback_switch_words");
        words(c, 0xa82e1, 0xa8327, "bcc45_asm_operand_switch_words");
        words(c, 0xa24d0, 0xa24d8, "bcc45_fixup_serializer_switch_words");
        c.comment(0xa7c50, "BI01: adjacent switch data, not another function or extension of the preceding terminal-inclusive body. Near WORD targets stay in the containing CS; no FAR prototype inferred.");
    }

    private void words(Context c, long start, long end, String name) throws Exception {
        c.data(start, new ArrayDataType(WORD, (int) ((end - start) / 2), 2));
        c.label(start, name);
    }

    private void applyRecordDomains(Context c, DataType far) throws Exception {
        StructureDataType piece = partial("SectionPiece28Partial", 28, "RF04 NE56:0041 allocation of001c through9a26; separate from control arenas and fixup records.");
        piece.replaceAtOffset(2, WORD, 2, "text_buffer_position", null);
        piece.replaceAtOffset(4, WORD, 2, "final_extent", "Closure computes section position minus start unless WORD12=ffff; not only reserved branch bytes.");
        piece.replaceAtOffset(0xa, WORD, 2, "section_start", null);
        piece.replaceAtOffset(0xc, WORD, 2, "branch_code_flags", null);
        piece.replaceAtOffset(0xe, WORD, 2, "target_link", "Actual9b12/9b1a resolution remains conditional.");
        piece.replaceAtOffset(0x12, WORD, 2, "fixup_count_or_sentinel", null);
        piece.replaceAtOffset(0x1a, WORD, 2, "piece_flags", "Branch code18 sets mask02.");
        resolve(c, piece);
        StructureDataType control = partial("ControlNode16Partial", 16, "RF04 first arena9b0a contribution; three0010 allocations are independent. No synchronized arena offsets inferred.");
        control.replaceAtOffset(2, WORD, 2, "control_flags", "0100 is BYTE3 mask01, not code WORD8 high flags.");
        control.replaceAtOffset(4, WORD, 2, "logical_request_index", "Captured9a99, not allocator offset or physical-byte position.");
        control.replaceAtOffset(6, WORD, 2, "request_count", null);
        control.replaceAtOffset(8, WORD, 2, "control_code", null);
        control.replaceAtOffset(0xe, WORD, 2, "target", null);
        resolve(c, control);
        StructureDataType fixup = partial("FixupQueueRecord8", 8, "BI01 NE56:0132 requests8 under9a2e; not the later independently allocated parallel99de/99e6 records.");
        fixup.replaceAtOffset(0, WORD, 2, "piece_relative_position", null);
        fixup.replaceAtOffset(2, far, 4, "request_pair", "Incoming DWORD, not an inferred resolved symbol pointer.");
        fixup.replaceAtOffset(6, WORD, 2, "fixup_class", "Class1 is a fixup domain, not operand kind1.");
        resolve(c, fixup);
    }

    private void applyPseudoregisters(Context c, DataType far) throws Exception {
        StructureDataType row = partial("PseudoregisterRow7", 7, "RF02 current registration reads name WORD0, selector WORD2 and type-selector BYTE4; trailing bytes unknown.");
        row.replaceAtOffset(0, WORD, 2, "name_offset", "Qualified initial NE7 table spelling, not a flat pointer.");
        row.replaceAtOffset(2, WORD, 2, "register_selector", null);
        row.replaceAtOffset(4, BYTE, 1, "type_selector", "Category-indexed current6eaa FAR-pointer table.");
        DataType rowType = resolve(c, row);
        // Three source-qualified rows, not an invented full-table extent.
        for (long offset : new long[] { 0x165c6, 0x165cd, 0x1660c }) {
            c.data(offset, rowType);
        }
        c.label(0x165c6, "bcc45_pseudoregister_EAX_row");
        c.label(0x165cd, "bcc45_pseudoregister_EDX_row");
        c.label(0x1660c, "bcc45_pseudoregister_AX_row");
        c.comment(0x165c6, "RF02: seven-byte rows; _EAX selector0/type0a, _EDX selector2/type0a, _AX selector0/type08. BYTE1979!=0 prefixes @ only for selected selectors and skips others (_EDX skipped); no unconditional spelling registration, game ABI or historical compiler attribution.");
        StructureDataType symbol = partial("SymbolPartial", 0x23, "RF02 class7 registration/current-symbol selector path; extent is a minimum touched-field envelope, not proven allocation size.");
        symbol.replaceAtOffset(0xe, far, 4, "type_pair", null);
        symbol.replaceAtOffset(0x16, WORD, 2, "register_selector", "Selector lookup reads current symbol, not node cached WORD10.");
        symbol.replaceAtOffset(0x22, BYTE, 1, "symbol_class", null);
        resolve(c, symbol);
        StructureDataType node = partial("SymbolReferenceNodePartial", 0x12, "RF02 tag5 constructor writes selected fields; not a control-node16 or complete allocation contract.");
        node.replaceAtOffset(0, WORD, 2, "node_tag", null);
        node.replaceAtOffset(2, WORD, 2, "node_category", "Current type WORD0, distinct numeric domain from node tag.");
        node.replaceAtOffset(4, WORD, 2, "flags", "Incoming flags masked001f.");
        node.replaceAtOffset(8, far, 4, "type_pair", null);
        node.replaceAtOffset(0xc, far, 4, "symbol_pair", null);
        node.replaceAtOffset(0x10, WORD, 2, "cached_selector", "Not the field used by current-symbol lookup32:0f60.");
        resolve(c, node);
        enumType(c, "NodeTag", new String[] { "typed_literal", "symbol_reference", "or_capable", "outer_comparison" }, new long[] { 2, 5, 0x1c, 0x1f });
        enumType(c, "NodeCategory", new String[] { "category7", "category8", "category9", "category10" }, new long[] { 7, 8, 9, 10 });
        enumType(c, "BackendRecordTag", new String[] { "selector16", "selector32", "literal", "conditional_cf" }, new long[] { 9, 10, 12, 0xcf });
        enumType(c, "InstructionRequestTag", new String[] { "or_request", "cmp_request", "push_request", "mov_request", "shld_request" }, new long[] { 0x5e, 0x9c, 0xae, 0xbb, 0xfe });
        c.comment(0x6ea71, "RF02 NE36:[1c71,1db4) is registration-loop coverage, not a complete function extent: stride7 until name WORD0; intern15:383f, class7 creation31:089b, row WORD2 -> symbol WORD16. No whole containing-function boundary inferred.");
        c.label(0x6ea71, "bcc45_pseudoregister_registration_fragment");
        c.data(0x17584, new ArrayDataType(BYTE, 12, 1));
        c.label(0x17584, "bcc45_register_encoding_map12");
    }

    private void enumType(Context c, String name, String[] names, long[] values) {
        EnumDataType type = new EnumDataType(TYPES, name, 2);
        type.setDescription("Descriptive selected BCC4.5 values only; numeric domain is not interchangeable with adjacent enums or recovered historical identifiers.");
        for (int i = 0; i < names.length; i++) {
            type.add(names[i], values[i]);
        }
        resolve(c, type);
    }

    private void applyControlState(Context c) throws Exception {
        StructureDataType option = partial("BooleanOptionRow8", 8, "BI02/RF03 initial option row; handler interpretation is conditional and current-DS based.");
        option.replaceAtOffset(0, BYTE, 1, "key", null);
        option.replaceAtOffset(1, BYTE, 1, "threshold", null);
        option.replaceAtOffset(2, WORD, 2, "near_handler", "Current NE36 CS, not a FAR callback.");
        option.replaceAtOffset(4, WORD, 2, "runtime_ds_destination", "Offset only; runtime DS validity and state are not inferred from initial image bytes.");
        resolve(c, option);
        c.data(0x140c6, option);
        c.label(0x140c6, "bcc45_option_k_row");
        c.comment(0x140c6, "RF03: lowercase k/threshold2/near0636/destination1997. '-' writes0, '+' or NUL1, '.' conditional snapshot restore; store precedes suffix validation without rollback. This row does not write199a or1a0f.");
        StructureDataType storeOption = partial("ByteStoreOptionRow8", 8, "BI02 byte-store handler08b5 row, distinct from Boolean0636 and delegation089d interpretations.");
        storeOption.replaceAtOffset(0, BYTE, 1, "key", null);
        storeOption.replaceAtOffset(1, BYTE, 1, "threshold", null);
        storeOption.replaceAtOffset(2, WORD, 2, "near_handler", null);
        storeOption.replaceAtOffset(4, WORD, 2, "runtime_ds_destination", "Offset only, not a resolved live DS address.");
        storeOption.replaceAtOffset(6, BYTE, 1, "stored_byte", "Read before destination WORD; no trailing-input validation in this handler.");
        DataType storeRow = resolve(c, storeOption);
        for (long row : new long[] { 0x14306, 0x1430e, 0x142a6, 0x142ae, 0x143ce, 0x143d6, 0x143de, 0x143e6 }) {
            c.data(row, storeRow);
            c.program().getReferenceManager().addMemoryReference(c.mapped(row + 2), c.mapped(0x6d6b5), ghidra.program.model.symbol.RefType.DATA, ghidra.program.model.symbol.SourceType.ANALYSIS, 0);
        }
        c.label(0x14306, "bcc45_W_wildcard_state_rows");
        c.label(0x142a6, "bcc45_WS_state_rows");
        c.label(0x143ce, "bcc45_Y_state_rows");
        c.comment(0x14306, "BI02 ordered W wildcard stores199a=0 then96ae=1; later S delegation reaches WS NUL row1ca6 ->1a0f=4. A cleared199a therefore does not imply the header gate is zero. Current rows/input/segments, signed threshold and preservation are required; no accepted-run state inferred.");
        c.comment(0x143ce, "BI02/RF03 Y NUL/-/f/n rows select199a=1/0/1/2. Separate root Y rows clear96ae and1a0f first; these rows do not clear1997.");
        c.comment(0xad8df, "ZF01 selected normalizer stores: source kind1, selector copy after tag009c + ffc2 ->005e; no general claim that arithmetic flags survive C statements or categories retype their operands.");
    }
}
