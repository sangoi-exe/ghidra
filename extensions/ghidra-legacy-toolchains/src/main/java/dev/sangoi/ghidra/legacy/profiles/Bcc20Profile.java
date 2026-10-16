package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Exact original BCC2.0 image; FBOV blocks are static analysis coordinates, not loaded selectors. */
public final class Bcc20Profile extends ToolchainProfile {
    public static final String ID = "bcc20-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/BCC20");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final long DS = 0xeef0;

    // R117/R125/R131/R137/R148/R160/R168/R174 at Johnny cutoff5e6c9dbe.
    // Manager table identifier, original resident paragraph, original body FILE, code size, fixup bytes.
    // These are the selected recorded rows, not an FBOV directory parser.
    private static final int[][] BODIES = {
        { 0x0338, 0x0c85, 0x43a60, 0x10c7, 0x009a },
        { 0x0378, 0x0caf, 0x4b6b0, 0x0522, 0x0048 },
        { 0x03e0, 0x0ce6, 0x54350, 0x0151, 0x0008 },
        { 0x0458, 0x0d30, 0x62db0, 0x019c, 0x002a },
        { 0x0460, 0x0d33, 0x62f80, 0x01fb, 0x0024 },
        { 0x0470, 0x0d38, 0x631b0, 0x10c4, 0x0044 },
        { 0x0488, 0x0d48, 0x650a0, 0x0753, 0x0028 },
        { 0x0490, 0x0d4f, 0x65830, 0x0f2e, 0x003c },
        { 0x0498, 0x0d58, 0x667c0, 0x02b1, 0x0012 },
        { 0x04a0, 0x0d5c, 0x66a90, 0x2251, 0x0184 },
        { 0x04c8, 0x0d6d, 0x69d70, 0x0ceb, 0x008a },
        { 0x04f8, 0x0d8e, 0x6e460, 0x11b5, 0x0110 },
        { 0x0508, 0x0d96, 0x6f8c0, 0x09f3, 0x0010 },
        { 0x0510, 0x0d9d, 0x702d0, 0x1209, 0x00aa },
        { 0x0598, 0x0dd8, 0x78700, 0x1057, 0x014a }
    };

    public Bcc20Profile() {
        super(ID, "Old-style DOS Executable (MZ)", 502432, "dd5744b99c6fa61dc1d95c580a1f1d6f1b3e97ae8b920dd6e9cfedce29f82fb6");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        projectBodies(c, monitor);
        applyOptions(c);
        applyNodesAndNames(c);
        applyBackends(c);
        applyRequests(c);
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        c.function(0x43d7a, 0x43db2, "bcc20_submit_option_table", 6, "R1740338:[031a,0352); far wrapper RETF6; I/L+zero and other+ffff bypasses; normal return restores SI.");
        c.function(0x43db2, 0x43dfc, "bcc20_dispatch_near_options", 6, "R1740338:[0352,039c); near RET6, FF5402 handler call. Tagged INC-BP/POP-BP/DEC-BP frame; cleanup is six argument bytes, not a FAR prototype. Successful handlers do not end scanning.");
        c.function(0x43dfc, 0x43e65, "bcc20_boolean_option_handler", 6, "R1740338:[039c,0405); near RET6, tagged BP frame; saves/restores SI/DI only with intact frame. First suffix byte only, no suffix validation or rollback invented.");
        c.function(0x43fc7, 0x43fe1, "bcc20_delegate_option_table", 6, "R1740338:[0567,0581); near RET6 forwards descriptor+4 and unchanged input FAR pair.");
        c.function(0x43d5b, 0x43d7a, "bcc20_transfer_option_bytes60", 0, "R1740338:[02fb,031a); copies current643a+i to08bc+4*i, i0..59; not S/B/c intake.");
        c.function(0x54350, 0x54386, "bcc20_reuse_linked_slot_or_append", 6, "R13703e0:[0000,0036); separate reuse helper calls0056 when empty. Constructor bypasses this helper.");
        c.function(0x543a6, 0x54435, "bcc20_append_arena", 6, "R13703e0:[0056,00e5); returns saved old used offset, restores incoming SI/DI on normal intact-frame return. Capacity/growth and ffff error handling are conditional; descendant effects unproved.");
        c.function(0x66899, 0x66900, "bcc20_construct_two_array_node", 8, "R117/R1370498:[00d9,0140); two four-byte appends; first returned U selects immediate primary stores. Counter C read after opaque04e0 callback; U=4*C, U=V and callback SI/base preservation remain unproved.");
        c.function(0x6526e, 0x6529d, "bcc20_record_for_current_id", 2, "R1170488:[01ce,01fd); current889e list, reload current8894 at access groups; zero return does not add a caller guard.");
        c.function(0x67e1a, 0x6802c, "bcc20_recognize_current_text_section", 0, "R11704a0:[138a,159c); exact_TEXT comparator can OR88ac bit8 before other guards. Mismatch does not clear it; remaining branches/descendants not fully recovered.");
        c.function(0x6824e, 0x682c1, "bcc20_construct_helper_prefix_node", 4, "R11704a0:[17be,1831); model16ef and88ac bit8 choose N_/F_; rereads bit AFTER814c callback to choose77/78. No buffer bounds, arbitrary callback preservation or historical invocation inferred.");
        c.function(0x682c1, 0x682ec, "bcc20_select_helper_suffix", 2, "R11704a0:[1831,185c); suffix index4*record0+2*record2 wraps16, no bounds check; selected526b/526d contain528b (lxmul@).");
        c.function(0xba87, 0xbaa8, "bcc20_compare_terminated_bytes", 8, "R117 resident0110:0007; sign-extended eight-bit difference, CLD/LODSB/SCASB, restores DS/SI/DI; not unrestricted strcmp semantics.");
        c.function(0xc072, 0xc09d, "bcc20_copy_terminated_wrapper", 8, "R117 resident0160:0002; source length+1 passed to transfer boundary, not arbitrary extent/pointer validity.");
        c.function(0xc146, 0xc180, "bcc20_append_terminated_wrapper", 8, "R117 resident0170:0006; adds destination length only to offset, no segment carry.");
        c.function(0x62dc6, 0x62f0b, "bcc20_section_reset_caller", 4, "R1250458:[0016,015b); conditional caller, not per-file scheduling proof.");
        c.function(0x62f80, 0x6317b, "bcc20_initialize_section_state_and_backend", 4, "R125/R1600460:[0000,01fb); selected fill zeros889e..88b9 including88ac at fill return only. Final fresh BYTE1714 chooses installed backend; downstream state survival unproved.");
        c.function(0x650a0, 0x651f0, "bcc20_construct_section_list_record", 8, "R1250488:[0000,0150); selected27-byte record name+11 from frame+0a, counter+4 and link state; no upstream name/CLI handoff inferred.");
        c.function(0x65930, 0x659a8, "bcc20_capture_current_section_id", 20, "R1250490:[0100,0178); frame+0e ->86d6; independent clear86d4..86f4 does not include88ac; descendant effects remain conditional.");
        c.function(0x65db7, 0x65e44, "bcc20_dispatch_section_recognition", 6, "R1250490:[0587,0614); conditional direct recognizer call after opaque callbacks/current addressed tests.");
        c.function(0xbf23, 0xbf51, "bcc20_fill_bytes", 8, "R125 resident0150:0003; CLD/alignment/STOSW/tail, returns incoming destination DX:AX and restores SI/DI on normal return; valid extent required.");
        c.function(0x1402, 0x1418, "bcc20_copy_callback_table_bytes", 8, "R131 resident0000:0402; CLD/REP MOVSB forward copy, restores DS/SI/DI on normal return.96-byte installation requires valid views/no defeating aliases.");
        c.function(0x633c8, 0x6344c, "bcc20_install_obj_callbacks", 4, "R1600470:[0218,029c); source546e,current87cc,count0060.86d2&1 controls optional.obj suffix, not backend selection.");
        c.function(0x78803, 0x788fa, "bcc20_install_asm_callbacks", 4, "R1310598:[0103,01fa); source5552,current87cc,count0060; lifetime and output descendants remain conditional.");
        c.function(0x631b0, 0x63200, "bcc20_append_backend_byte", 2, "R1600470:[0000,0050); low argument BYTE only; current883e/8840 bound, growth path and current883c segment; ADD/ADC current section+0c/+0e after returning store, no physical writer semantics.");
        c.function(0x78f38, 0x79244, "bcc20_asm_instruction_serializer", 2, "R1310598:[0838,0b44); saves SI/DI on intact returning protocol. Selected77/78 near/far selectors and conditional78 PUSH-CS/near-CALL request; callbacks/current context and physical output remain unproved.");
        c.function(0x78de6, 0x78e86, "bcc20_instruction_size_contribution", 2, "R1310598:[06e6,0786); sign-extended descriptor byte+2 plus operand contributions, not raw byte+2 alone as final encoded size.");
        c.function(0x78e86, 0x78f30, "bcc20_operand_size_contribution", 4, "R1310598:[0786,0830); selected operand contribution, not complete encoding proof.");
        c.function(0x792ca, 0x795a6, "bcc20_asm_operand_formatter", 4, "R1310598:[0bca,0ea6); selected kind5 selectors12/15 request near/far and ptr literals; other kinds/context have separate paths.");
        c.function(0x795da, 0x79622, "bcc20_asm_segment_prefix", 2, "R1310598:[0eda,0f22); current record/group/name predicates and opaque callbacks remain conditional.");
        c.function(0x6a642, 0x6a6a5, "bcc20_request_output_character", 2, "R13104c8:[08d2,0935); buffered or opaque descendant requests, not completed physical output/preservation proof.");
        c.function(0x6a9bc, 0x6aa04, "bcc20_request_output_string", 4, "R13104c8:[0c4c,0c94); traversal or forwarded FAR pair; descendant effects unexpanded.");
        c.function(0x6ea47, 0x6ee25, "bcc20_request_function_frame", 0, "R14804f8:[05e7,09c5); fresh frame predicates select ENTER0092 or numeric-selector PUSH0094/MOV009c/SUB0028 requests; no historical control or physical output claim.");
        c.function(0x6fa2e, 0x6fa53, "bcc20_capture_immediate_request", 6, "R1480508:[016e,0193); frame amount+6,selector+8,tag+0a; initializes only selected8b28/8b2c/8b31/8b36 fields then near0243.");
        c.function(0x6f982, 0x6f99f, "bcc20_lower_node_tag_request", 4, "R1310508:[00c2,00df); builds current operand workspace, clears second kind and dispatches tag.");
        c.function(0x6fb03, 0x6fda5, "bcc20_normalize_instruction_request", 2, "R131/R1480508:[0243,04e5); current SUB0028 amount2/kind4/firstkind1 can request DEC005b twice. Pending/auxiliary/current87f4 callbacks can intervene; no unconditional flags, context or output equivalence.");
        c.function(0x6fda5, 0x6fe45, "bcc20_flush_auxiliary_request", 2, "R1310508:[04e5,0585); saves/restores SI/DI normally, current pending0057 and operand-kind edits remain conditional.");
        c.function(0x6fe45, 0x700e1, "bcc20_build_operand_workspace", 4, "R1310508:[0585,0821); nine-byte workspace, ID*4 array addressing;77/78 can select kind5 only under recorded record predicates, not universally.");
        c.function(0x6405a, 0x64137, "bcc20_shorten_immediate_request", 6, "R1680470:[0eaa,0f87); near RET6; tested descriptor flag WORD+3, selected current SUB amount2 yields conditional83/EC/02 byte requests, not physical encoding proof.");
        c.function(0x64137, 0x641a1, "bcc20_request_immediate_bytes", 2, "R1680470:[0f87,0ff1); near RET2; current kind4/adjustment3 requests low amount BYTE once; descendant effects remain open.");
        c.function(0x63251, 0x63265, "bcc20_map_register_selector", 2, "R1680470:[00a1,00b5); near RET2; signed BYTE index and signed BYTE result; selected0b maps04, not a universal unsigned register enum.");
        log.appendMsg(ID, "Applied exact recorded FBOV analysis blocks, selected complete functions, partial layouts and qualified static references. Original overlay words remain unrelocated; no runtime selector, simultaneous residency, generic FBOV support or historical invocation is asserted.");
    }

    private int word(Context c, long file) throws Exception {
        return Byte.toUnsignedInt(c.original().getOriginalByte(file)) | Byte.toUnsignedInt(c.original().getOriginalByte(file + 1)) << 8;
    }

    private long dword(Context c, long file) throws Exception {
        return word(c, file) | (long) word(c, file + 2) << 16;
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(ID + ": " + message);
        }
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private StructureDataType partial(String name, int size, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, size);
        type.setDescription(description + " Unknown bytes remain undefined; descriptive analysis layout, not a recovered historical C type.");
        return type;
    }

    private DataType farStorage(Context c) {
        StructureDataType type = partial("FarStorage16", 4, "Original offset and segment storage; interpretation is qualified separately for each MZ or FBOV source.");
        type.replaceAtOffset(0, WORD, 2, "offset", null);
        type.replaceAtOffset(2, WORD, 2, "segment_field", "MZ paragraphs and FBOV table identifiers are different coordinate domains.");
        return resolve(c, type);
    }

    private void reference(Context c, long source, long destination) {
        c.program().getReferenceManager().addMemoryReference(c.mapped(source), c.mapped(destination), RefType.DATA, SourceType.ANALYSIS, 0);
    }

    private void mzWord(Context c, long source, int paragraph, long targetFile) throws Exception {
        require(word(c, source) == paragraph, "changed original MZ paragraph at FILE " + Long.toHexString(source));
        Address address = c.mapped(source);
        int loaded = Short.toUnsignedInt(c.program().getMemory().getShort(address));
        require(c.program().getRelocationTable().getRelocations(address).stream().anyMatch(r -> r.getStatus() == Relocation.Status.APPLIED && r.getType() == 0 && r.getValues() != null && r.getValues().length == 3 && (r.getValues()[2] & 0xffff) == loaded), "missing applied native MZ relocation at " + address);
        var space = (SegmentedAddressSpace) c.program().getAddressFactory().getDefaultAddressSpace();
        require(space.getAddress(loaded, 0).equals(c.mapped(targetFile)), "native MZ relocation/file projection disagrees at " + address);
    }

    private void projectBodies(Context c, TaskMonitor monitor) throws Exception {
        require(word(c, 0x18ce0) == 0x4246 && word(c, 0x18ce2) == 0x564f, "changed FBOV header at the declared resident end");
        mzWord(c, 0x1001, 0x0def, DS);
        StructureDataType descriptor = partial("RecordedOverlayDescriptor32Partial", 32, "R117 manager descriptor; only this image's selected rows are projected. Header/stub allocation is not an executable runtime model.");
        descriptor.replaceAtOffset(4, WORD, 2, "archive_relative_file_offset_low", "ADD/ADC pair+4/+6 plus original FILE18cf0, not a paragraph base.");
        descriptor.replaceAtOffset(6, WORD, 2, "archive_relative_file_offset_high", null);
        descriptor.replaceAtOffset(8, WORD, 2, "body_bytes", null);
        descriptor.replaceAtOffset(10, WORD, 2, "fixup_list_bytes", "WORD site offsets follow body; low-bit-one fixups are not modeled.");
        resolve(c, descriptor);
        for (int[] body : BODIES) {
            monitor.checkCancelled();
            long resident = 0x1000L + 16L * body[1];
            mzWord(c, 0xc390L + body[0], body[1], resident);
            require(word(c, resident) == 0x3fcd && dword(c, resident + 4) + 0x18cf0 == body[2] && word(c, resident + 8) == body[3] && word(c, resident + 10) == body[4], "changed recorded descriptor for table identifier " + Integer.toHexString(body[0]));
            String name = String.format("bcc20_fbov_%04x_analysis", body[0]);
            var memory = c.program().getMemory();
            MemoryBlock block = memory.getBlock(name);
            if (block == null) {
                require(memory.locateAddressesForFileBytesOffset(c.original(), body[2]).isEmpty(), "already mapped FBOV body outside this profile's block");
                block = memory.createInitializedBlock(name, c.program().getAddressFactory().getDefaultAddressSpace().getAddress(0), c.original(), body[2], body[3] + body[4], true);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(true);
                block.setComment("Exact BCC2.0 recorded body + raw fixup words, FILE " + Integer.toHexString(body[2]) + ". Overlay offset zero is an analysis coordinate only: not a loaded CS/selector or simultaneous-residency claim. No original or memory segment fields are patched.");
            }
            require(block.isOverlay() && block.getSize() == body[3] + body[4] && block.getStart().equals(c.mapped(body[2])) && block.getEnd().equals(c.mapped((long) body[2] + body[3] + body[4] - 1)), "conflicting existing analysis block " + name);
            byte[] original = new byte[body[3] + body[4]];
            byte[] mapped = new byte[original.length];
            require(c.original().getOriginalBytes(body[2], original) == original.length && memory.getBytes(block.getStart(), mapped) == mapped.length && java.util.Arrays.equals(original, mapped), "preserving changed body bytes in " + name);
            // Native MZ block adjustment splits the0490 descriptor at+6. Keep its mapping and the proved ADD/ADC WORD pair rather than spanning native blocks with a32-byte object or DWORD.
            c.data(resident + 4, WORD);
            c.data(resident + 6, WORD);
            c.data(resident + 8, WORD);
            c.data(resident + 10, WORD);
            c.label(resident, String.format("bcc20_fbov_%04x_descriptor", body[0]));
            c.label(body[2], String.format("bcc20_fbov_%04x_body", body[0]));
            reference(c, 0xc390L + body[0], resident);
            reference(c, resident + 4, body[2]);
            words(c, (long) body[2] + body[3], (long) body[2] + body[3] + body[4], String.format("bcc20_fbov_%04x_raw_fixup_sites", body[0]));
            c.comment(body[2], "R117/R125/R131/R137/R148/R160/R168/R174 recorded row " + Integer.toHexString(body[0]) + "; mapped original body and raw fixup list only. Unreviewed body bytes remain unclassified. Stored FAR segment words are manager-table identifiers, NOT paragraphs or resolved runtime selectors. Qualified references are static DATA relationships, not unconditional execution edges.");
        }
    }

    private int[] body(int identifier) {
        for (int[] body : BODIES) {
            if (body[0] == identifier) {
                return body;
            }
        }
        throw new IllegalArgumentException("Unrecorded FBOV identifier");
    }

    private long stub(Context c, int identifier, int stubOffset, int bodyOffset) throws Exception {
        int[] body = body(identifier);
        long file = 0x1000L + 16L * body[1] + stubOffset;
        require(word(c, file) == 0x3fcd && word(c, file + 2) == bodyOffset && c.original().getOriginalByte(file + 4) == 0 && bodyOffset < body[3], "changed qualified stub FILE " + Long.toHexString(file));
        c.label(file, String.format("bcc20_fbov_%04x_stub_%04x", identifier, stubOffset));
        reference(c, file + 2, (long) body[2] + bodyOffset);
        c.comment(file, "Qualified INT3f stub to original FILE " + Long.toHexString((long) body[2] + bodyOffset) + "; DATA projection into static analysis block, not a runtime loaded-selector/call rewrite.");
        return file;
    }

    private void overlayFar(Context c, int owner, long source, int targetIdentifier, int stubOffset, int bodyOffset) throws Exception {
        require(word(c, source) == stubOffset && word(c, source + 2) == targetIdentifier && (targetIdentifier & 7) == 0, "changed selected overlay FAR field");
        requireOverlaySite(c, owner, source + 2);
        long targetStub = stub(c, targetIdentifier, stubOffset, bodyOffset);
        reference(c, source, targetStub);
        reference(c, source, (long) body(targetIdentifier)[2] + bodyOffset);
        c.comment(source, "Selected original FBOV low-three-bits-zero field: table " + Integer.toHexString(targetIdentifier) + ", stub " + Integer.toHexString(stubOffset) + ", proved body " + Integer.toHexString(bodyOffset) + ". Raw words deliberately retained; this DATA reference is not an applied runtime relocation or dynamic call guarantee. Low-bit-one special handling is outside this profile.");
    }

    private void requireOverlaySite(Context c, int owner, long segmentFile) throws Exception {
        int[] body = body(owner);
        boolean found = false;
        for (long fixup = (long) body[2] + body[3]; fixup < (long) body[2] + body[3] + body[4]; fixup += 2) {
            found |= word(c, fixup) == segmentFile - body[2];
        }
        require(found, "selected segment field absent from actual FBOV fixup list");
    }

    private void overlayResidentFar(Context c, int owner, long source, int identifier, int offset, int paragraph) throws Exception {
        require(word(c, source) == offset && word(c, source + 2) == identifier && (identifier & 7) == 0, "changed selected overlay-to-resident field");
        requireOverlaySite(c, owner, source + 2);
        long resident = 0x1000L + 16L * paragraph;
        mzWord(c, 0xc390L + identifier, paragraph, resident);
        reference(c, source, resident + offset);
        c.comment(source, "R117/R131 selected fixup-listed low-bits-zero FBOV field joins manager table " + Integer.toHexString(identifier) + " through its native MZ-relocated paragraph to resident FILE " + Long.toHexString(resident + offset) + ". Raw overlay words remain unchanged; qualified static DATA relation, not a paragraph interpretation of the stored identifier or executed call proof.");
    }

    private void words(Context c, long start, long end, String name) throws Exception {
        c.data(start, new ArrayDataType(WORD, (int) ((end - start) / 2), 2));
        c.label(start, name);
    }

    private void applyOptions(Context c) throws Exception {
        StructureDataType option = partial("OptionDescriptor8Partial", 8, "R174 same-CS near-handler option row. Qualification sign-extends BYTE1 against signed current WORD14e4, not the BCC3.1 unsigned-byte test.");
        option.replaceAtOffset(0, BYTE, 1, "literal_key", null);
        option.replaceAtOffset(1, BYTE, 1, "signed_qualification", null);
        option.replaceAtOffset(2, WORD, 2, "near_handler", "Current0338 CS, never an MZ paragraph or FAR callback.");
        option.replaceAtOffset(4, WORD, 2, "current_ds_target", "Offset only; current runtime DS and input remain prerequisites.");
        DataType row = resolve(c, option);
        for (long file : new long[] { 0x1075e, 0x10766, 0x10796 }) {
            c.data(file, row);
            reference(c, file + 2, 0x43dfc);
            reference(c, file + 4, DS + word(c, file + 4));
        }
        c.label(0x1075e, "bcc20_option_B_row");
        c.label(0x10766, "bcc20_option_S_row");
        c.label(0x10796, "bcc20_option_c_row");
        c.comment(0x10766, "R174 literal B/S/c rows target current1715/1714/16fc, qualification0 requires signed WORD14e4<=0. NUL/+ stores1, '-'0, '.' SAVES current byte into819e+(target-16ee) when14e4!=0; not BCC3.1 restoration. No complete CLI/default/scheduling claim.");
        words(c, 0x43e65, 0x43e75, "bcc20_boolean_handler_key_target_words");
        c.label(0x4ba9a, "bcc20_post_parser_ordered_OR_fragment");
        c.comment(0x4ba9a, "R174 partial0378:[03ea,040f): first c16fc|=freshS1714, then S1714|=freshB1715, no retroactive B-to-c OR. Not a complete containing function or established parser-to-selector lifetime.");
        c.label(0x43ade, "bcc20_mode_supplier_fragment");
        c.comment(0x43ade, "R174 partial preceding-result/callback route reaches stores1715=1 then1714=1 at43b2b..43b33; not proof literal S/B handlers are the only suppliers.");
        for (int offset : new int[] { 0x16fc, 0x1714, 0x1715 }) {
            c.data(DS + offset, BYTE);
            c.label(DS + offset, String.format("bcc20_initial_state_%04x", offset));
        }
    }

    private void applyNodesAndNames(Context c) throws Exception {
        StructureDataType append = partial("AppendDescriptor8Partial", 8, "R137 independent append arena. Growth effects/base validity and returned-offset/counter identity are not established.");
        append.replaceAtOffset(0, WORD, 2, "current_segment", "Initial image projection only, not a resolved runtime allocation.");
        append.replaceAtOffset(2, WORD, 2, "capacity", "Unsigned comparison in append0056.");
        append.replaceAtOffset(4, WORD, 2, "used_offset", "Saved old value is returned in AX.");
        append.replaceAtOffset(6, WORD, 2, "linked_reuse_head", "Read by separate0000 helper, not the constructor's direct0056 append.");
        DataType arena = resolve(c, append);
        c.data(DS + 0x8680, arena);
        c.data(DS + 0x8698, arena);
        c.label(DS + 0x8680, "bcc20_primary_node_array_descriptor");
        c.label(DS + 0x8698, "bcc20_secondary_node_array_descriptor");
        StructureDataType primary = partial("PrimaryNode4Partial", 4, "R117/R137 separate four-byte primary array, not a BCC3.1 five-WORD record.");
        primary.replaceAtOffset(0, BYTE, 1, "node_tag", "Selected77/78; byte domain, distinct from instruction request tags.");
        primary.replaceAtOffset(1, BYTE, 1, "flags", null);
        primary.replaceAtOffset(2, BYTE, 1, "temporary_selector", "Consumer saves/replaces withff and conditionally restores through current SI.");
        resolve(c, primary);
        StructureDataType secondary = partial("SecondaryNode4Partial", 4, "Separate secondary array; no equality of arena offsets or identity with returned node counter asserted.");
        secondary.replaceAtOffset(0, WORD, 2, "callback_result", null);
        secondary.replaceAtOffset(2, WORD, 2, "argument_word", null);
        resolve(c, secondary);
        EnumDataType tags = new EnumDataType(TYPES, "NodeTag8", 1);
        tags.add("selected77", 0x77);
        tags.add("selected78", 0x78);
        resolve(c, tags);
        overlayFar(c, 0x0498, 0x668a9, 0x03e0, 0x002f, 0x0056);
        overlayFar(c, 0x0498, 0x668b9, 0x03e0, 0x002f, 0x0056);
        overlayFar(c, 0x04a0, 0x67e27, 0x0488, 0x0061, 0x01ce);
        overlayFar(c, 0x04a0, 0x682b5, 0x0498, 0x0034, 0x00d9);
        overlayResidentFar(c, 0x04a0, 0x67e43, 0x0110, 0x0007, 0x0aa8);
        overlayResidentFar(c, 0x04a0, 0x6827e, 0x0160, 0x0002, 0x0b07);
        overlayResidentFar(c, 0x04a0, 0x6828c, 0x0170, 0x0006, 0x0b14);
        overlayFar(c, 0x0458, 0x62f03, 0x0460, 0x0020, 0x0000);
        overlayFar(c, 0x0490, 0x65e3a, 0x04a0, 0x0048, 0x138a);
        for (int[] literal : new int[][] { { 0x141b8, 6 }, { 0x141e7, 3 }, { 0x141ea, 3 }, { 0x1417b, 7 } }) {
            c.data(literal[0], new ArrayDataType(BYTE, literal[1], 1));
        }
        words(c, DS + 0x526b, DS + 0x526f, "bcc20_selected_helper_suffix_cells");
        reference(c, DS + 0x526b, 0x1417b);
        reference(c, DS + 0x526d, 0x1417b);
        c.label(DS + 0x88ac, "bcc20_initial_section_flags");
        c.comment(DS + 0x88ac, "Initial compiler DS projection only: _TEXT equality ORs0008; reset fill clears it only at its return boundary. Prefix and post-callback tag reads are separate current reads, not a snapshotted invariant.");
    }

    private void applyBackends(Context c) throws Exception {
        DataType far = farStorage(c);
        for (long table : new long[] { 0x1435e, 0x14442 }) {
            c.data(table, new ArrayDataType(far, 24, 4));
            c.label(table, table == 0x1435e ? "bcc20_obj_source_callbacks24" : "bcc20_asm_source_callbacks24");
            c.comment(table, "R131/R160 initial24 FAR cells/96bytes, all segment words have native MZ relocation. Conditional CLD/REP MOVSB installation to current DS87cc..882b. Slot+28 becomes current87f4 only while table/context survive; DATA references are possible source/stub relationships, not unconditional calls or copied runtime state.");
            for (int i = 0; i < 24; i++) {
                long cell = table + 4L * i;
                int paragraph = word(c, cell + 2);
                long segmentFile = 0x1000L + 16L * paragraph;
                mzWord(c, cell + 2, paragraph, segmentFile);
                reference(c, cell, segmentFile + word(c, cell));
            }
        }
        reference(c, 0x14386, stub(c, 0x0470, 0x0057, 0x03e6));
        reference(c, 0x14386, 0x63596);
        reference(c, 0x1446a, stub(c, 0x0598, 0x002a, 0x0838));
        reference(c, 0x1446a, 0x78f38);
        c.label(0x63596, "bcc20_obj_instruction_callback_prefix");
        c.comment(0x63596, "R160/R168 partial0470:[03e6,0456),112bytes/46instructions through computed dispatch; NOT a complete function. Descriptor3f98+19*tag, workspaces8b28/8b31; preparation descendants and other arms unreviewed.");
        overlayFar(c, 0x0460, 0x63166, 0x0598, 0x0034, 0x0103);
        overlayFar(c, 0x0460, 0x63173, 0x0470, 0x0025, 0x0218);
        overlayFar(c, 0x0470, 0x631c6, 0x03e0, 0x002f, 0x0056);
        words(c, 0x79264, 0x79270, "bcc20_asm_call_selector_words");
        words(c, 0x795a6, 0x795da, "bcc20_operand_formatter_dispatch_words");
        words(c, 0x7105b, 0x7105d, "bcc20_node77_consumer_dispatch_cell");
        c.label(0x70b80, "bcc20_common_node77_78_consumer_fragment");
        c.comment(0x70b80, "R1310510:[08b0,08ea) partial common path; temporary primary+2=ff, secondary WORD+2=0, current post-call SI/base controls restoration. Not a whole consumer function, nor proof U=4*C.");
        overlayFar(c, 0x0510, 0x70ba8, 0x0508, 0x002a, 0x00c2);
    }

    private void applyRequests(Context c) throws Exception {
        StructureDataType descriptor = partial("InstructionDescriptor19Partial", 19, "R148/R168 tag-indexed descriptor at3f98+19*tag. Overlapping WORD+4 is not the tested flag field+3.");
        descriptor.replaceAtOffset(0, WORD, 2, "mnemonic_ds_offset", null);
        descriptor.replaceAtOffset(2, BYTE, 1, "signed_size_contribution", null);
        descriptor.replaceAtOffset(3, WORD, 2, "unaligned_flags", "SUB descriptorC100 at+3; +4 reads03c1 and is only an overlapping word.");
        descriptor.replaceAtOffset(7, BYTE, 1, "immediate_class", null);
        descriptor.replaceAtOffset(13, WORD, 2, "encoding_word_0d", null);
        descriptor.replaceAtOffset(15, WORD, 2, "encoding_word_0f", null);
        descriptor.replaceAtOffset(17, WORD, 2, "encoding_word_11", null);
        DataType row = resolve(c, descriptor);
        EnumDataType tags = new EnumDataType(TYPES, "InstructionRequestTag16", 2);
        String[] names = { "sub_request", "dec_request", "enter_request", "push_request", "mov_request", "call77_request", "call78_request" };
        int[] values = { 0x28, 0x5b, 0x92, 0x94, 0x9c, 0x77, 0x78 };
        for (int i = 0; i < values.length; i++) {
            long file = DS + 0x3f98 + 19L * values[i];
            tags.add(names[i], values[i]);
            c.data(file, row);
            c.label(file, "bcc20_descriptor_" + names[i]);
            reference(c, file, DS + word(c, file));
        }
        resolve(c, tags);
        c.data(DS + 0x54ce, new ArrayDataType(BYTE, 12, 1));
        c.label(DS + 0x54ce, "bcc20_register_encoding_map12");
        words(c, 0x63eab, 0x63ead, "bcc20_SUB_dispatch_cell");
        words(c, 0x63f11, 0x63f13, "bcc20_DEC_dispatch_cell");
        reference(c, 0x63eab, 0x63cb2);
        reference(c, 0x63f11, 0x637fb);
        c.label(0x63cb2, "bcc20_SUB_byte_request_fragment");
        c.label(0x637fb, "bcc20_DEC_register_request_fragment");
        c.comment(0x637fb, "R168 partial0470:[064b,0663): current firstkind1,selector0b ->map04,+48->BYTE4c request. No whole callback or guaranteed two-DEC traversal inferred.");
        stub(c, 0x04f8, 0x0020, 0x05e7);
        stub(c, 0x0508, 0x004d, 0x016e);
        stub(c, 0x0488, 0x0066, 0x0000);
        stub(c, 0x0490, 0x0020, 0x0100);
        c.comment(0x6fd99, "R160 actual indirect CALL current DS87f4 at0508:04d9;04d8 is preceding PUSH SI. Initial source tables give static alternatives only; no current installed-state or unconditional body call reference.");
    }
}
