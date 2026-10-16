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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Original-file facts for the retained R117 BCC3.1 image, not compiler attribution. */
public final class Bcc31Profile extends ToolchainProfile {
    public static final String ID = "bcc31-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/BCC31");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final long DS_FILE = 0x13c00;

    // R160 source tables, reread through the canonical NE parser against the exact original.
    // Each row is a raw movable entry ordinal and its resolved original FILE target, not a selector.
    private static final int[][] OBJECT_CALLBACKS = {
        { 0x02aa, 0x9093a }, { 0x02ae, 0x9197a }, { 0x02b2, 0x917f2 },
        { 0x02af, 0x91452 }, { 0x02b0, 0x91772 }, { 0x029d, 0x91868 },
        { 0x02ab, 0x919d6 }, { 0x02ad, 0x91a10 }, { 0x02a9, 0x909c8 },
        { 0x02ac, 0x91531 }, { 0x02bb, 0x8ecb3 }, { 0x02a6, 0x8c0b8 },
        { 0x02a5, 0x8c0df }, { 0x02ba, 0x8ebb3 }, { 0x02a8, 0x90d47 },
        { 0x02b9, 0x8e75c }, { 0x02b8, 0x8e76b }, { 0x02b1, 0x919b1 },
        { 0x02a7, 0x8c120 }, { 0x02c1, 0x8eb6d }, { 0x02b7, 0x8ec62 },
        { 0x02b4, 0x8eb96 }, { 0x02b6, 0x8ec20 }, { 0x02b5, 0x8e7e9 },
        { 0x02c0, 0x8e4af }, { 0x02bf, 0x8e941 }
    };
    private static final int[][] ASM_CALLBACKS = {
        { 0x02de, 0x928b6 }, { 0x02c8, 0x9466a }, { 0x02ce, 0x945d6 },
        { 0x02c9, 0x94400 }, { 0x02ca, 0x94542 }, { 0x02cd, 0x945fd },
        { 0x02c6, 0x947a9 }, { 0x02c7, 0x94848 }, { 0x02da, 0x9259c },
        { 0x02c5, 0x9492e }, { 0x02dd, 0x92b33 }, { 0x02d9, 0x91f80 },
        { 0x02d8, 0x91f8e }, { 0x02df, 0x927ac }, { 0x02c4, 0x9478e },
        { 0x02db, 0x91fa9 }, { 0x02dc, 0x91fb8 }, { 0x02cb, 0x94909 },
        { 0x02cc, 0x948d8 }, { 0x02e0, 0x9272d }, { 0x02d6, 0x92863 },
        { 0x02d5, 0x92772 }, { 0x02d4, 0x92896 }, { 0x02d3, 0x91fcd },
        { 0x02d2, 0x930ab }, { 0x02d1, 0x92126 }
    };

    public Bcc31Profile() {
        super(ID, "New Executable (NE)", 672150, "87c6dfbad817eeca31c069043f08063f7122663e51932ad089e6d1c563450d3b");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        DataType far = farStorage(c);
        options(c);
        backends(c, far);
        appendAndNodes(c);
        instructionDescriptors(c);
        events(c, far);
        recordPreparation(c, far);
        numericLowering(c);
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        c.function(0x55d58, 0x55d98, "bcc31_option_table_wrapper", 6, "R174/R294 NE38:[0558,0598), FAR wrapper with mode-dependent I/L/FFFF bypasses; preserves SI on intact normal return, not arbitrary callee effects.");
        c.function(0x55d98, 0x55deb, "bcc31_near_option_dispatch", 6, "R174 NE38:[0598,05eb), tagged INC BP near frame, wildcard and unsigned BYTE qualification; current descriptor WORD+2 is a near call, not FAR callback.");
        c.function(0x55deb, 0x55e5b, "bcc31_boolean_option_store", 6, "R174 NE38:[05eb,065b), near RET6; empty/plus stores1, leading minus stores0, other first bytes fail except guarded dot. Dot requires nonzero1827 and RESTORES saved DS[6d98+u16(target-1a65)] to freshly reread target. This guard conflicts with the selected zero-qualified rows' dispatch guard; no successful B/S/c dot spelling inferred. Saves SI/DI on intact normal return; no universal ES/flags ABI.");
        c.function(0x56045, 0x5605f, "bcc31_option_descriptor_delegate", 6, "R174 NE38:[0845,085f), near RET6; delegates current descriptor+4 table and unchanged far input to dispatcher.");
        c.function(0x56713, 0x567a6, "bcc31_P_control_supplier", 6, "R294 NE38:[0f13,0fa6), near RET6. Stores DS1aed=1 before opaque NE2:51c9; freshly reads suffix after call, leading '-' stores0 even with trailing bytes. Optional dot and up-to-three copied bytes into1829..182b, tail NUL up to182c, scan length unbounded. All three local exits AX1, not invalid-suffix rejection. Survival to callback selection0166, other writers/defaults and historical -P use unknown. Same-image help advertises Force C++ compile, not command execution evidence.");
        c.function(0x8eae6, 0x8eb6d, "bcc31_install_object_callbacks", 4, "R160 NE66:[06e6,076d), complete RETF4 installer. Source DS5974->8b36, CX0034 REP MOVSW; forward-copy contract conditional DF0. Later882a&1 controls lowercase .obj suffix request, not backend selection.");
        c.function(0x92312, 0x9243c, "bcc31_install_asm_callbacks", 4, "R160 NE68:[0512,063c), complete RETF4 installer. Source DS5a5a->8b36, CX0034 REP MOVSW; forward-copy contract conditional DF0. Later882a&1 controls lowercase .asm suffix request, not CLI policy.");
        c.function(0x7241a, 0x724ac, "bcc31_word_array_append", 6, "R143 NE51:[121a,12ac), RETF6. Saves old descriptor+4, compares finite17-bit size sum againstffff, error and growth calls opaque. Fresh LES stores actual post-call SI capacity+2 and DI used+4; AX reloads saved old used-offset. Saves/restores SI/DI on intact normal return, not global ABI/base/copy/allocation effects.");
        c.function(0x7a0b0, 0x7a177, "bcc31_construct_five_word_array_node", 10, "R143 NE55:[18b0,1977), RETF10. Five independent WORD2 appends; only first returned offset U retained in DI. Immediate stores use U through fresh array selectors. Tag overwrites all AX before low-kind AL replacement, so kind AH comes from tag (0090/0091->0), not last append return. Unexpanded08aa can change later DI/state. Counter8859 read/increment occurs afterward; no U=2*C or five-array synchronization proved.");
        c.function(0x804b4, 0x80548, "bcc31_construct_qualified_helper_node", 4, "R117/R143 NE58:[2eb4,2f48), RETF4. Model1a66=0 or flags8ab8&8 gates naming path; actual returned FAR pair and current post-call SI feed node025d with tag0090/0091. Returned counter C is doubled and used with fresh8871 to OR1000, distinct from allocation offset U. No historical naming-control invocation inferred.");
        c.function(0x8e49b, 0x8e4af, "bcc31_signed_selector_mapping", 2, "R168 NE66:[009b,00af), near RET2 including full c20200 at00ac. CBW indexes current DS59dc by signed input BYTE then sign-extends result; old00ae end was truncated.");
        c.function(0x8fb88, 0x8fce9, "bcc31_shorten_immediate_request", 6, "R168 NE66:[1788,18e9), near RET6. Actual unaligned descriptor+3 test and current kind/selector/model/high-low amount select adjustment; subsequent opaque byte/ModRM effects and fresh descriptor+7 remain prerequisites. Selected SUB2 arithmetic requests83 ec02 conditionally, not a universal shortening theorem.");
        c.function(0x8fce9, 0x8fdbe, "bcc31_request_immediate_bytes", 2, "R168 NE66:[18e9,19be), near RET2. Fresh second-kind dispatch; selected kind4 reads current low amount BYTE, adjustment3 avoids additional-byte routes. Post-child SI preservation and other helper effects not inferred from local epilogue.");
        c.function(0x8e400, 0x8e44d, "bcc31_append_backend_byte", 2, "R168 NE66:[0000,004d), RETF2. Consumes low argument BYTE only; below current capacity stores/increments used, otherwise calls opaque NE51:121a. Fresh record+0e/+10 ADD/ADC accounts one; no complete OMF or physical output contract.");
        c.function(0x73b30, 0x73ba8, "bcc31_event_factory", 0, "R275 NE52:[0330,03a8), RETF. Three independent0010-byte allocations, separate event/metadata/pending views. Initializes event+4 from8859 and metadata+a=ffff indexed by event SI, not demonstrably the independent metadata allocation return; returns first offset, does not select JE or prove equal offsets/free-list histories.");
        c.function(0x7403d, 0x740ad, "bcc31_insert_event_chain", 6, "R275 NE52:[083d,08ad), RETF6. Opaque084d precedes current-state link writes. Updates883a or anchor.next, prev links and pending WORD0; final zero successor unguarded, writable sentinel/valid view required. No universal arena/lifetime proof.");
        c.function(0x74b23, 0x74c4f, "bcc31_compose_event_chains", 4, "R275 NE52:[1323,144f), RETF4. Conditional zero-kind/code or contiguous-position merge copies code+8 then target+e then ORs flags+2 before free-list calls. Otherwise links source.prev/destination.next; opaque free-list effects and aliases remain unproved.");
        c.function(0x74eec, 0x74f15, "bcc31_walk_kind4_events", 0, "R275 NE52:[16ec,1715), RETF. Loads main root883a, saves current event.next+a before kind4 dispatch; saved-register protocol permits subsequent saved-next advance, not list validity/termination or unchanged arbitrary state.");
        c.function(0x8b200, 0x8b21d, "bcc31_prepend_private_event", 2, "R275 NE64:[0000,001d), near RET2. Private root8e1a, not main root883a; no shared membership claim.");
        c.function(0x8b21d, 0x8b37f, "bcc31_dispatch_event_input", 2, "R275 NE64:[001d,017f), RETF2. Follows metadata+4/+6 pair; zero pair clears kind. Current flags0004, finite span/count and1a79 select producer017f or unreviewed05c0. Saves SI/DI on intact returning protocol, not acyclicity/count nonwrap.");
        c.function(0x8b37f, 0x8b7c0, "bcc31_produce_selected_branch_events", 8, "R275 NE64:[017f,05c0), near RET8. Saved q uses model1a67=3 and earlier flags0004; later fresh flags0004 and saved q select JE or JNE-plus-JE. Distinct allocation provenance is not proved numerical inequality: JE target saved02ef return, JNE target later0429 return. Composition may transfer code/target identity before consumer; opaque request effects/current frame/selector/alias premises remain.");
        c.function(0x79644, 0x79b29, "bcc31_copy_selected_event", 4, "R275 reused NE55:[0e44,1329), RETF4. Copies old code+8/target+e after factory124a, clears old fields; new flags0010 at1300, NOT0100. Does not initially choose JE or establish whole caller lifetime.");
        c.function(0x85200, 0x8543d, "bcc31_consume_branch_events", 4, "R275 reused NE61:[0000,023d), RETF4. Selected kind0/4/5 reads code+8,target+e through current8891 after preludes/callbacks; downstream current branch wrappers separate from historical event creation/traversal.");
        c.function(0x3ee24, 0x3ee31, "bcc31_identity_far_pair", 4, "R289 NE28:[4824,4831), complete13-byte/6-instruction RETF4 leaf: loads frame BP+8->DX and BP+6->AX, no dereference/helper. Returns supplied pair only with valid frame/return protocol; does not establish current7f64 selects it.");
        c.function(0x9400, 0x950b, "bcc31_argument_selection_helper", 4, "R291 NE3:[0000,010b), complete267-byte/88-instruction RETF4 body. Argument FAR+8/+a reaches sampled BYTE+d and followed FAR+4 WORD0 comparison0012; alternative FAR+10/+12 or finite current pair tables remain raw fields, not Event16. Physical argument chronology and current indirect8b42/8b3e/8b3a are conditional. Both local exits forward actual final opaque call DX:AX, not an explicit reload of input or saved pair; numerical identity/replacement and transitive effects unproved.");
        c.function(0x74826, 0x74af2, "bcc31_prepare_record_children", 4, "R329/R333 NE52:[1026,12f2), complete716-byte/261-instruction RETF4 body; adjacent five-WORD dispatch table excluded. Recursively replaces child pairs high-before-low through freshly loaded parent views and conditionally writes BYTE6 using finite signed/partial-register arithmetic. All eight exits freshly load current frame BP+8 into DX, THEN BP+6 into AX; not an unconditional input identity, different-pointer result or pure function. Opaque12fc, aliases, recursion termination, descendant cleanup and actual R310 traversal/source type remain unproved.");
        c.function(0x7ebfc, 0x7ef99, "bcc31_lower_numeric_record", 4, "R320 NE58:[15fc,1999), complete925-byte/350-instruction RETF4 body; adjacent16-WORD table excluded. Actual021d result overwrites current frame high then low. Numeric WORD2 dispatch, current1a67 and signed BYTE6 select ordered requests and current saved child/result words. Fifteen real FAR fields and24 near calls do not establish P/E/K/2172 prototypes or operation names. Thirteen POP SI/LEAVE/RETF4 envelopes restore saved SI only with intact frame/stack and applicable descendant cleanup; return DX:AX/effects are route-dependent, not a universal ABI or source-type theorem.");
        c.function(0x7eff2, 0x7f607, "bcc31_numeric_lowering_parent", 6, "R320 NE58:[19f2,2007), byte-complete1557-byte/553-instruction RETF6 body with PARTIAL semantic coverage only: [19f2,1ac3),[1ebb,1ee8),[1f92,2007). Actual021d result overwrites BP+a/BP+8; current post-2281 SI and fresh saved-second fields gate the numeric0010 zero-pair arm. Qualified success calls15fc then jumps1fe6, bypassing immediate pcmp@ construction; no actual R310 path or source type proved. Remaining arms, opaque calls and transitive effects unreviewed. Existing2eb4 constructor is reused, not a duplicate function or stronger ABI.");
        log.appendMsg(ID, "Qualified option/control suppliers, 52 static FAR-table references, separate WORD arrays, instruction descriptors and event views applied. Current callbacks/state, allocation correspondence and historical invocation remain conditional; no universal ABI or whole-tool recovery.");
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private StructureDataType partial(String name, int length, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, length);
        type.setDescription(description + " Analysis field-role names only; unknown bytes remain undefined, not recovered historical C.");
        return type;
    }

    private DataType farStorage(Context c) {
        StructureDataType type = partial("FarStorage16", 4, "Stored offset/selector pair, not a flat pointer or a selector-validity assertion.");
        type.replaceAtOffset(0, WORD, 2, "offset", null);
        type.replaceAtOffset(2, WORD, 2, "selector", null);
        return resolve(c, type);
    }

    private void nearDataReference(Context c, long source, long target) {
        c.program().getReferenceManager().addMemoryReference(c.mapped(source), c.mapped(target), RefType.DATA, SourceType.ANALYSIS, 0);
    }

    private void options(Context c) throws Exception {
        StructureDataType row = partial("NearOptionDescriptor8Partial", 8, "R174/R294: case-exact key, unsigned qualifier, same-CS near handler and descriptor-dependent WORD+4. Final WORD has no established role.");
        row.replaceAtOffset(0, BYTE, 1, "key", null);
        row.replaceAtOffset(1, BYTE, 1, "minimumQualifier", null);
        row.replaceAtOffset(2, WORD, 2, "nearHandlerOffset", "Current CS, not FAR storage");
        row.replaceAtOffset(4, WORD, 2, "handlerArgument", "B/S/c: target DS byte; P: no role inferred");
        DataType option = resolve(c, row);
        for (int offset : new int[] { 0x1c1d, 0x1c25, 0x1c55, 0x1c9d }) {
            c.data(DS_FILE + offset, option);
        }
        c.label(0x1581d, "bcc31_option_B");
        c.label(0x15825, "bcc31_option_S");
        c.label(0x15855, "bcc31_option_c");
        c.label(0x1589d, "bcc31_option_P");
        for (long source : new long[] { 0x1581f, 0x15827, 0x15857 }) {
            nearDataReference(c, source, 0x55deb);
        }
        nearDataReference(c, 0x1589f, 0x56713);
        nearDataReference(c, 0x15821, DS_FILE + 0x1a98);
        nearDataReference(c, 0x15829, DS_FILE + 0x1a97);
        nearDataReference(c, 0x15859, DS_FILE + 0x1a73);
        c.comment(0x1581d, "R174: selected eight-byte rows before the disk handler sentinel, not whole-parser/CLI coverage. Zero-qualified B/S/c require current BYTE DS1827=0 (unsigned comparison); FF wildcard behavior exists separately. Dispatcher advances input offset only modulo65536, calls current near WORD+2 and continues scanning after nonzero AX. No case folding or invocation/history inferred.");
        c.farReference(0x56726, 2, 0x51c9, 0x7dc9);
        for (int offset : new int[] { 0x1827, 0x1a73, 0x1a97, 0x1a98, 0x1aed }) {
            c.data(DS_FILE + offset, BYTE);
        }
        c.label(DS_FILE + 0x1827, "bcc31_current_option_qualifier");
        c.label(DS_FILE + 0x1a97, "bcc31_current_backend_selector");
        c.label(DS_FILE + 0x1a98, "bcc31_current_B_supplier");
        c.label(DS_FILE + 0x1a73, "bcc31_current_c_supplier");
        c.label(DS_FILE + 0x1aed, "bcc31_current_P_control");
        c.label(0x523ea, "bcc31_ordered_mode_join_fragment");
        c.comment(0x523ea, "R174 NE35:[03ea,0403) is a partial tail, not a complete function: first BYTE1a73 |= current1a97, then BYTE1a97 |= current1a98. B's newly set S does not retroactively enter c. Separate partial NE38:021b..0223 can store1 to B then S; no only-writer or initialized/default/history claim.");
        c.comment(DS_FILE + 0x1a97, "On-disk initial byte is not historical compiler state. R160 NE57:01e3 freshly selects nonzero ASM/zero object only if current loaded context and intervening effects permit.");
    }

    private void backends(Context c, DataType far) throws Exception {
        for (int family = 0; family < 2; family++) {
            long source = family == 0 ? 0x19574 : 0x1965a;
            int[][] callbacks = family == 0 ? OBJECT_CALLBACKS : ASM_CALLBACKS;
            c.data(source, new ArrayDataType(far, 26, 4));
            c.label(source, family == 0 ? "bcc31_object_source_callbacks26" : "bcc31_asm_source_callbacks26");
            c.comment(source, "R160:26 singleton nonadditive NE FAR cells, raw target ff/movable entry ordinal, not imported segment paragraphs. Conditional REP MOVSW installation to current DS8b36 copies52 WORDs/104 bytes only with DF=0 at copy, valid views and no defeating effects/aliases. No local CLD; preceding NE2:51c9 does not prove DF/DS preservation. Displacement28h supplies current8b5e; DATA references are static possibilities, not unconditional calls or installed-state proof.");
            for (int i = 0; i < callbacks.length; i++) {
                c.farReference(source + 4L * i, 0xff, callbacks[i][0], callbacks[i][1]);
            }
        }
        c.data(DS_FILE + 0x8b36, new ArrayDataType(far, 26, 4));
        c.label(DS_FILE + 0x8b36, "bcc31_mutable_callback_workspace26");
        c.comment(DS_FILE + 0x8b36, "Mutable FAR storage, not direct calls. Current8b5e source slot+28 is object entry02bb->NE66:08b3 or ASM02dd->NE68:0d33 only while qualifying forward installation and current values survive. Other callback writers, scheduling and lifetime remain unknown.");
        c.label(0x8ecb3, "bcc31_object_callback_partial");
        c.comment(0x8ecb3, "R160 only NE66:[08b3,0940) prefix through computed dispatch is covered; not a complete function extent. Uses19-byte descriptor4128 and current8e2b/8e38 workspace. Preparation/output descendants unproved.");
        c.label(0x92b33, "bcc31_asm_callback_partial");
        c.comment(0x92b33, "R160 only NE68:[0d33,0dd1) prefix and separate[0e6d,0e7c) mnemonic fragment are covered; not a complete function extent. Tag91 requests push/call literals conditionally; whole formatter/sink/encoding effects unproved.");
    }

    private void appendAndNodes(Context c) throws Exception {
        StructureDataType descriptor = partial("WordArrayAppendDescriptor8Partial", 8, "R143: separate WORD-array segment and append capacity/used offsets. Unknown trailing WORD; no interleaved node record or allocator ABI.");
        descriptor.replaceAtOffset(0, WORD, 2, "currentArraySelector", "Node reloads this word as a segment, not a near array pointer");
        descriptor.replaceAtOffset(2, WORD, 2, "capacityOffset", "Unsigned append capacity comparison");
        descriptor.replaceAtOffset(4, WORD, 2, "usedOffset", "Saved old used-offset returned by append");
        DataType append = resolve(c, descriptor);
        for (int offset : new int[] { 0x8871, 0x87ca, 0x87c2, 0x87ba, 0x87b2 }) {
            c.data(DS_FILE + offset, append);
            c.label(DS_FILE + offset, "bcc31_word_array_descriptor_" + Integer.toHexString(offset));
            c.comment(DS_FILE + offset, "R143 one of five independent two-byte append descriptors, not a field of an interleaved node. Equal append sizes do not establish equal old offsets, synchronized histories or valid corresponding storage. First returned offset U must equal u16(2*C) for returned counter C to address the same slot; that invariant is unproved.");
        }
        EnumDataType tag = new EnumDataType(TYPES, "HelperNodeTag", 2);
        tag.add("flag8_set_request", 0x90);
        tag.add("flag8_clear_request", 0x91);
        tag.setDescription("R117/R143 selected node tags only, not an instruction/event enum or a recovered historical name.");
        resolve(c, tag);
        c.data(DS_FILE + 0x8859, WORD);
        c.label(DS_FILE + 0x8859, "bcc31_node_counter_not_allocation_offset");
        for (long source : new long[] { 0x7a0bc, 0x7a0c9, 0x7a0d4, 0x7a0df, 0x7a0ea }) {
            c.farReference(source, 51, 0x121a, 0x7241a);
        }
        c.farReference(0x8051b, 0xff, 0x025d, 0x7a0b0);
        c.farReference(0x80530, 0xff, 0x025d, 0x7a0b0);
    }

    private void instructionDescriptors(Context c) throws Exception {
        EnumDataType tags = new EnumDataType(TYPES, "InstructionRequestTag", 2);
        tags.add("SUB", 0x2e);
        tags.add("DEC", 0x73);
        tags.setDescription("R168 selected request/dispatch tags only, distinct from HelperNodeTag and EventBranchCode.");
        resolve(c, tags);
        StructureDataType descriptor = partial("InstructionDescriptor19Partial", 19, "R168 selected SUB descriptor; tested unaligned WORD+3 is not the distinct overlapping WORD+4 read.");
        descriptor.replaceAtOffset(0, WORD, 2, "mnemonicOffset", "Current DS near literal offset");
        descriptor.replaceAtOffset(3, WORD, 2, "testedMaskWord", "Actual unaligned WORD+3; SUB=c100, mask8000");
        descriptor.replaceAtOffset(7, BYTE, 1, "immediateAdjustmentSelector", null);
        descriptor.replaceAtOffset(13, WORD, 2, "word0d", null);
        descriptor.replaceAtOffset(15, WORD, 2, "modrmExtraWord", null);
        descriptor.replaceAtOffset(17, WORD, 2, "word11", null);
        DataType instruction = resolve(c, descriptor);
        StructureDataType overlapping = partial("InstructionDescriptor19OverlapReadPartial", 19, "Alternative overlapping view, not a second physical field after WORD+3: SUB WORD+4=03c1 differs from tested+3=c100.");
        overlapping.replaceAtOffset(4, WORD, 2, "overlappingWord4", null);
        resolve(c, overlapping);
        c.label(DS_FILE + 0x4128, "bcc31_instruction_descriptors_base");
        c.data(0x18092, instruction);
        c.label(0x18092, "bcc31_SUB_descriptor_tag002e");
        c.comment(0x18092, "R168 DS4128+19*002e=4492. Exact19 bytes2955fe00c1030002020a0a0a00000029002d00. WORD+3=c100 versus overlapping WORD+4=03c1; +7=02,+0f=0029,+11=002d. No whole-instruction or node/event enum equivalence.");
        nearDataReference(c, 0x18092, DS_FILE + 0x5529);
        c.data(DS_FILE + 0x59dc, new ArrayDataType(BYTE, 12, 1));
        c.label(DS_FILE + 0x59dc, "bcc31_selected_selector_mapping12");
        c.comment(DS_FILE + 0x59dc, "R168 selected12-byte window000402060307010506070504, not complete signed-index table extent. Mapping sign-extends input BYTE and result BYTE; selector0b reads04. No unrestricted unsigned register enum.");
        c.data(0x8f984, WORD);
        c.data(0x8fa0e, WORD);
        c.label(0x8f984, "bcc31_SUB_dispatch_cell");
        c.label(0x8fa0e, "bcc31_DEC_dispatch_cell");
        nearDataReference(c, 0x8f984, 0x8f6c0);
        nearDataReference(c, 0x8fa0e, 0x8ef81);
        c.label(0x8f6c0, "bcc31_SUB_dispatch_fragment");
        c.label(0x8ef81, "bcc31_DEC_register_fragment");
        c.label(0x8fdbe, "bcc31_ModRM_register_fragment");
        c.comment(0x8f6c0, "R168 partial NE66:[12c0,12d0), not a complete function. Tag002e static same-CS dispatch from1528+2*tag. Selected current ordinary route can request83 ec02; not a complete byte/object output or historical traversal.");
        c.comment(0x8ef81, "R168 partial NE66:[0b81,0b9c), not a complete function. DEC tag0073 and current register selector0b can request4c. Existence does not import BCC2.0's amount-two normalizer rule.");
        c.comment(0x8fdbe, "R168 partial NE66:[19be,19e4), not a complete function; only selected register ModRM branch, memory/fallback routes unreviewed.");
        c.farReference(0x8e413, 51, 0x121a, 0x7241a);
    }

    private void events(Context c, DataType far) throws Exception {
        EnumDataType codes = new EnumDataType(TYPES, "EventBranchCode", 2);
        codes.add("JE", 0xa);
        codes.add("JNE", 0xb);
        codes.setDescription("R275 actual mnemonic/opcode/inverse-table join, not historical instruction emission.");
        DataType code = resolve(c, codes);
        // The parallel16-byte event views and their actual producers/consumers are deliberately separate.
        StructureDataType event = partial("Event16Partial", 16, "R275 separate event allocation through current selector8891; no metadata/pending allocation identity implied.");
        event.replaceAtOffset(0, WORD, 2, "kind", null);
        event.replaceAtOffset(2, WORD, 2, "flags", null);
        event.replaceAtOffset(4, WORD, 2, "factoryCounterWord", "Factory stores current DS8859; no stronger global position identity");
        event.replaceAtOffset(6, WORD, 2, "positionLengthWord", "Finite arithmetic quantity; not universal source or output length");
        event.replaceAtOffset(8, code, 2, "branchCode", "Only selected JE/JNE values named; other codes remain numeric");
        event.replaceAtOffset(10, WORD, 2, "nextOffset", null);
        event.replaceAtOffset(12, WORD, 2, "previousOffset", null);
        event.replaceAtOffset(14, WORD, 2, "targetOffset", null);
        resolve(c, event);
        StructureDataType metadata = partial("EventMetadata16Partial", 16, "R275 separate metadata allocation through current8889; only selected followed far input and initialized link are established.");
        metadata.replaceAtOffset(4, far, 4, "inputNodePair", null);
        metadata.replaceAtOffset(8, WORD, 2, "suppliedCount", null);
        metadata.replaceAtOffset(10, WORD, 2, "factoryInitializedWordA", "FFFF store indexes metadata view with event SI; equal independent allocation offsets unproved");
        resolve(c, metadata);
        StructureDataType pending = partial("EventPending16Partial", 16, "R275 independent pending allocation, current8881 view; insertion writes WORD0, not proof of shared-offset allocation correspondence.");
        pending.replaceAtOffset(0, WORD, 2, "insertionWord", null);
        pending.replaceAtOffset(10, far, 4, "producerReadPair", "Observed offset/segment reads only; meaning unknown");
        resolve(c, pending);
        c.data(DS_FILE + 0x587c, new ArrayDataType(WORD, 2, 2));
        c.data(DS_FILE + 0x58a2, new ArrayDataType(BYTE, 2, 1));
        c.data(DS_FILE + 0x5960, new ArrayDataType(code, 2, 2));
        c.label(DS_FILE + 0x587c, "bcc31_JE_JNE_mnemonic_offsets");
        c.label(DS_FILE + 0x58a2, "bcc31_JE_JNE_short_opcodes");
        c.label(DS_FILE + 0x5960, "bcc31_JE_JNE_inverse_codes");
        nearDataReference(c, DS_FILE + 0x587c, DS_FILE + 0x58d0);
        nearDataReference(c, DS_FILE + 0x587e, DS_FILE + 0x58d3);
        c.comment(DS_FILE + 0x587c, "R275 pre-load DS587c/587e->58d0/58d3 je/jne;58a2/58a3=74/75;5960/5962=000b/000a. Current loaded DS/tables may change; static identity is not executed historical output.");
        c.data(0x8543d, new ArrayDataType(WORD, 6, 2));
        c.label(0x8543d, "bcc31_event_consumer_switch_words");
        c.label(0x74cc9, "bcc31_kind4_walker_driver_fragment");
        c.comment(0x74cc9, "R275 NE52:[14c9,14ce) one actual CALL, not complete driver. Other partial driver[16ae,16bc) passes actual post-pass DI to consumer; no whole-pass/historical lifetime inferred.");
        c.farReference(0x74cca, 0xff, 0x022b, 0x74eec);
        c.farReference(0x74f07, 0xff, 0x0298, 0x8b21d);
        for (long source : new long[] { 0x8b38c, 0x8b41b, 0x8b4e9, 0x8b4f0, 0x8b58b, 0x8b5a0, 0x8b62a }) {
            c.farReference(source, 0xff, 0x021e, 0x73b30);
        }
        for (long source : new long[] { 0x8b625, 0x8b68a, 0x8b783, 0x8b78c }) {
            c.farReference(source, 0xff, 0x021f, 0x74b23);
        }
        c.farReference(0x8b79c, 0xff, 0x0220, 0x7403d);
        callbackControl(c, far);
    }

    private void callbackControl(Context c, DataType far) throws Exception {
        c.data(0x13cc2, far);
        c.data(0x13cca, far);
        c.label(0x13cc2, "bcc31_identity_callback_source_cell");
        c.label(0x13cca, "bcc31_transformer_callback_source_cell");
        c.farReference(0x13cc2, 0xff, 0x000a, 0x3ee24);
        c.farReference(0x13cca, 0xff, 0x0009, 0x480b1);
        c.label(0x55943, "bcc31_argument_callback_install_fragment");
        c.comment(0x55943, "R289 NE38:[0143,019c) partial installation prefix, not a complete function. Earlier four-WORD00c2/00ca->7f64 copy is distinct from later32-WORD0114->81d5 constructor copy. Source selection uses fresh post-helper1aed&1; no CLD or lifetime proof.");
        c.label(0x480b1, "bcc31_argument_transformer_partial");
        c.comment(0x480b1, "R289 only NE30:[64b1,6667)438-byte prefix is covered, not a complete function despite local RETF4 exits. WORD2=0015/saved WORD0=4 forwards actual NE3:0000 result. WORD2=0014 call-free path follows old FAR+8, reads target+e then+c, writes input+a then+8, follows NOW-current FAR+8 and writes classification+2. Replacement/restart and opaque helpers remain qualified; current SI is not refreshed after rewrite; computed dispatch/table arms unreviewed.");
        c.farReference(0x480e5, 3, 0x0000, 0x9400);
        c.comment(DS_FILE + 0x1aed, "R294 supplier/control join to R289: installer NE38:0166 samples post-0161-call BYTE1aed bit0 into8188; zero selects identity NE28:4824, nonzero transformer NE30:64b1. Handler store survival through callbacks/writers/installer0161, defaults and historical -P ordering remain unproved. No direct calls inferred from mutable7f64.");
        c.data(DS_FILE + 0x8188, BYTE);
        c.label(DS_FILE + 0x8188, "bcc31_sampled_callback_control_bit");
        c.data(DS_FILE + 0x7f64, new ArrayDataType(far, 2, 4));
        c.label(DS_FILE + 0x7f64, "bcc31_mutable_argument_callback_pair");
        c.comment(DS_FILE + 0x7f64, "R289 four-WORD conditional installation atNE38:018e; requires DF0 at REP MOVSW, valid current segments/stack and nondefeating aliases/effects. Current indirect calls through7f64/7f68 are not unconditional static calls or historical invocation proof.");
    }

    private void recordPreparation(Context c, DataType far) throws Exception {
        StructureDataType record = partial("PreparationRecord20Partial", 20, "R329/R333 descriptive addressed-record view only, not Event16, a source-language type or permission to type unproved dynamic addresses.");
        record.replaceAtOffset(0, WORD, 2, "numericClassification", null);
        record.replaceAtOffset(2, WORD, 2, "numericLoweringClass", null);
        record.replaceAtOffset(4, WORD, 2, "testedFlags", "Selected class1 tests0010");
        record.replaceAtOffset(6, BYTE, 1, "annotationByte", "Signed reads and modulo-byte writes; later reloads remain fresh");
        record.replaceAtOffset(12, far, 4, "firstChildPair", "Recursive return stores high+e before low+c");
        record.replaceAtOffset(16, far, 4, "secondChildPair", "Recursive return stores high+12 before low+10");
        resolve(c, record);
        dispatchWords(c, 0x74af2, 0x73800, new int[] { 0x1081, 0x1091, 0x1091, 0x1120, 0x1091 });
        c.label(0x74af2, "bcc31_record_preparation_dispatch5");
        c.comment(0x74af2, "R329/R333 literal CS12f2 five-WORD data, outside the complete body. DATA references are static same-CS projections, not unconditional executable edges or proof that the table remains unchanged.");
        c.farReference(0x7ec0a, 0xff, 0x021d, 0x74826);
        c.farReference(0x7f004, 0xff, 0x021d, 0x74826);
        c.comment(0x748ad, "R333 current recursive DX is stored to parent+e BEFORE AX to+c through the same freshly loaded parent. Later LES reads the updated pair; calls/aliases may change the argument frame.");
        c.comment(0x74aa4, "R333 BYTE6 store precedes fresh L/R frame-local reads. Later12db reloads the parent before reading/negating BYTE6;12e4 store precedes fresh BP+8 then BP+6 return loads. Do not cache across these alias-sensitive stores.");
    }

    private void numericLowering(Context c) throws Exception {
        dispatchWords(c, 0x7ef99, 0x7d600, new int[] { 0x188d, 0x188d, 0x17ad, 0x17ad, 0x17ad, 0x17ad, 0x162b, 0x162b, 0x196d, 0x196d, 0x196d, 0x1994, 0x17ad, 0x17ad, 0x162b, 0x162b });
        c.label(0x7ef99, "bcc31_numeric_lowering_dispatch16");
        c.comment(0x7ef99, "R320 separate literal CS1999 WORD table for u16(WORD2-1)<=000f. Numeric classifications are not source types; same-CS DATA projections do not establish historical traversal or descendant semantics.");
        dispatchWords(c, 0x7f613, 0x7d600, new int[] { 0x1e12, 0x1e12, 0x1d37, 0x1d37, 0x1d37, 0x1d37, 0x1ac3, 0x1ac3, 0x1e99, 0x1e99, 0x1e99, 0x1fe6, 0x1d37, 0x1d37, 0x1acd, 0x1ebb });
        c.label(0x7f613, "bcc31_parent_numeric_dispatch16");
        c.comment(0x7f613, "R320 literal parent CS2013 table; cell2031=1ebb for numeric WORD2=0010. Other targets are literal projections only, not full semantic coverage of the parent arms.");
        c.data(0x1938d, new ArrayDataType(BYTE, 6, 1));
        c.data(0x193c2, new ArrayDataType(BYTE, 3, 1));
        c.data(0x193c5, new ArrayDataType(BYTE, 3, 1));
        c.label(0x1938d, "bcc31_pcmp_suffix");
        c.label(0x193c2, "bcc31_near_helper_prefix");
        c.label(0x193c5, "bcc31_far_helper_prefix");
        nearDataReference(c, 0x7f5dd, 0x1938d);
        nearDataReference(c, 0x804d4, 0x193c2);
        nearDataReference(c, 0x804e4, 0x193c5);
        for (int field : new int[] { 0x16bc, 0x1718, 0x174f, 0x176f, 0x17a4, 0x1834, 0x1873, 0x1914, 0x1953, 0x198a, 0x1fa2, 0x1fb2, 0x1fc2, 0x1fd2 }) {
            c.farReference(0x7d600 + field, 0xff, 0x0218, 0x79fc4);
        }
        for (int field : new int[] { 0x175f, 0x1863, 0x1943 }) {
            c.farReference(0x7d600 + field, 0xff, 0x025e, 0x7a22e);
        }
        c.farReference(0x7ef90, 0xff, 0x0273, 0x844cb);
        c.farReference(0x745b9, 0xff, 0x0217, 0x7eff2);
        c.comment(0x745b1, "R320 NE52:[0db1,0dbd) partial caller window only: pushes current BP+8,BP+6,DI before actual FAR call toNE58:19f2. Not a complete caller body or universal argument declaration.");
        c.comment(0x7f4bb, "R320 selected zero-pair arm: saved-second WORD0=2, CURRENT post-2281 SI=000a/000b and fresh second-record WORD+c OR WORD+e=0. Push saved-first high then low, call15fc at1ee2, jump1fe6. Qualified bypass of immediate pcmp@ constructor, not actual R310 traversal or source type; failed predicates enter unreviewed request arms.");
        c.comment(0x7f592, "R320 fresh1a95 zero selects immediate pcmp@ path1fdc; nonzero makes four actual0218 requests then jumps1c2b, not1fe6. This observed branch does not generalize to all parent arms or historical optimizer policy.");
        c.comment(0x7f5dc, "R320 literal lowercase pcmp@ suffix, then0055 and actual PUSH-CS/near call2eb4. Existing qualified constructor selects N_/F_ from current1a66/8ab8; no later case conversion, external spelling, serialization or executed call inferred.");
    }

    private void dispatchWords(Context c, long table, long segmentFile, int[] targets) throws Exception {
        c.data(table, new ArrayDataType(WORD, targets.length, 2));
        for (int i = 0; i < targets.length; i++) {
            nearDataReference(c, table + 2L * i, segmentFile + targets[i]);
        }
    }
}
