package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Exact retained TLINK5.1 NE facts; coordinates are FileBytes-qualified, not runtime selectors. */
public final class Tlink51Profile extends ToolchainProfile {
    public static final String ID = "tlink51-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/TLINK51");
    private static final DataType WORD = UnsignedShortDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final long CODE_FILE = 0x1200;
    private static final long SLOT_FILE = 0x11800;
    private static final int[][] INLINE_TEXT_JOINS = { {0xde2c, 0xde2f, 0xde37}, {0xde3f, 0xde42, 0xde4c}, {0xde4e, 0xde51, 0xde59}, {0xdeb2, 0xdeb5, 0xdec7}, {0xded1, 0xded4, 0xdee0}, {0xdee9, 0xdeec, 0xdef1}, {0xdefd, 0xdf00, 0xdf1c} };

    public Tlink51Profile() {
        super(ID, "New Executable (NE)", 150569, "ab8b8b96c1bde5ff6f56c8be2c3b928d21ead7430e72b01e3b22f1fa179ad006");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        if (!c.program().getLanguageID().toString().equals("x86:LE:16:Protected Mode")) {
            throw new IllegalStateException(ID + " requires native16-bit NE protected-mode import");
        }
        monitor.checkCancelled();
        types(c);
        writerAndFamilies(c, monitor);
        controlsAndAssociations(c, monitor);
        outputRecords(c, monitor);
        prepareInlineData(c);
        farSlots(c, monitor);
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        var writer = function(c, 0x3c0b, 0x3ca1, "rewrite_far_window_cf", "R118/K2: complete150-byte/51-instruction writer. Current09C0 array at058C selects descriptor in09D8; kind1/3 and word4==BX required. j=DX&03FF; old operand read before opcode rejection.9A→90 0E E8, EA→90 90 E9; j0 checks saved0282/0284 before0286 opcode and sets0CD6. Success addsF802 to fullDX, subtracts j/4/fresh058E fromCX and writes028E=FFFF/CF1; rejectionCF0. AX/SI/DI restored, finalES descriptor selector. Representative equality is not a universal physical-segment rule.");
        TlinkWriterContract.apply(c, writer, monitor);
        function(c, 0x3b87, 0x3c0b, "flush_rewrite_buffer", "R118: saves last opcode/current record boundary in0286/0284/0282. Carry-back0CD6 conditionally extends source/position backward1.9E96 is a buffer-copy request, not physical-I/O success.");
        window(c, 0x4f33, 0x4f97, "source_record_setup", "R118: selected setup partition, stores currentBX at058C, adjusted low/high record offset058E/0590, copied count058A and DS0CD8 buffer. Not a complete containing function or finalNE segment identity.", monitor);
        window(c, 0x3d18, 0x3d9c, "location_dispatch", "R118/R198 partial dispatcher, not entire function: (DH&1C)>>1 indexes table.0C→3D5A requires current01A9!=1 and special-class comparison inequality, calls3C0B at3D6E; acceptedCF skips3CA1.04→3D28 and14→3D73 are separate; imported-symbol40E5 return bypasses this dispatcher.", monitor);
        window(c, 0x42bf, 0x43b1, "selected_target_frame_writer_callers", "R118/K2: selected partial resolver with direct4302/432C writer calls; both require class0C/current01A9!=1. Frame50 carries target family key intoBX; other frame/import/thread paths differ.43AA derivesDI from updatedDX and clearsCF, so final resolverCF is not writerCF.", monitor);
        function(c, 0x7cb3, 0x7e58, "produce_entry_family", "K2: ordered combinable same-name family stores currentSI or rememberedCX into R+2. Sorting/list order/helper/current-state prerequisites remain; not descriptor number or packed selector.");
        function(c, 0x7f29, 0x7f55, "allocate_descriptor20", "K2: request14h via09D4; zero20 on usable return, storeSI at+4; separately increment087B and store at+6. Allocation/growth effects conditional.");
        function(c, 0x7f9c, 0x8391, "construct_family_descriptor", "K2: ordinary PUBLIC nonempty reuse requires equal name/class and combine controls, retains representative+4 while publishing R+0. New/empty/special packing branches differ; descriptor sharing is not final physical-segment equivalence.");
        function(c, 0xa901, 0xa97d, "classify_descriptor_kind", "K2: current attributes/special handles first; trailing literalCODE test can return1, other category3 also writer-accepted. Not universal CODE classification or historical identity.");
        window(c, 0x0493, 0x09a1, "option_parser_partition", "R126/R192: decoded parser partition only, selected f/v semantics, not all handlers. Normal reader AH raw/AL selectively folded; savedCH==lowercasef reaches0726→01A9=1.UppercaseF differs; trailing+/- is pushed back, not a latch toggle. Rawv has separate sign path; no historical config/current-value inference.", monitor);
        function(c, 0x03c0, 0x043f, "read_option_character", "R126: pending byte returns both halves unchanged; ordinary return AH raw/AL ASCII-folded, BX/CX/DX restored. Numeric INT21 state/results are unresolved, ES/flags not preserved.");
        function(c, 0x0baa, 0x0c64, "initialize_options", "R126: ES=DS clear42 bytes0180..01AA only with clearDF, including01A9/0186; then input composer/config attempt. No localCLD or historical defaults guaranteed. Relocated immediate0BD1 targetsNE1:0010, not literal16.");
        function(c, 0x0a2b, 0x0baa, "compose_option_input", "R126: conditional config/name and response input composition, parser calls0AE0/0B46. Service/helper returns, exact chosen config, BX/SI/DI preservation and historical controls are not inferred.");
        function(c, 0x00c4, 0x0119, "reset_working_controls", "R192: clears0019/001A, not0186. Complete body excludes subsequent inline-text startup path.");
        window(c, 0x0177, 0x01f9, "publish_current_working_controls", "R192 partial startup path;018B suppression can clear0186 and callDE08, then0197 freshly reads0186 before0019/001A stores. No preservation across diagnostic/helper or initializer-to-record lifetime implied.", monitor);
        function(c, 0xa046, 0xa06f, "traverse_record_controls", "R192: matching current record bytesFF/03 set0019 independently of option setter. Intact ordinary termination AND SI,SI givesCF0/ZF1, restoresBX/ES and leavesSI0; no allocator/record/API identity.");
        function(c, 0xa06f, 0xa089, "selected_control_traversals", "R192: actual A082 conditional0019=1 store exists but is not selected by either intact ordinary A046 clearCF return. No blanket syntactic unreachable or exclusive supplier claim.");
        function(c, 0xd84a, 0xd8e7, "supply_association_and_call", "R206: current chain/A4CE values supply089F/08A1/08A3/08A7; optionalzeroSI leaves089F untouched; clears08A5 and directly callsD8E7 atD8CE. Subsequent chain read reloadsES; no historical name or helper preservation inferred.");
        function(c, 0xd8e7, 0xd976, "construct_name_association", "R206: request12 then six-word currentDF copy from089F. Name bank08D8 and record bank0938 differ; full offsets retained around low3-bit bank selection. New record writes0/+2/+0C/flags20 before name binding; existing current10 permits+2 replacement and20-set/10-clear, otherwise copied association discarded. Allocation/error/helper state and extents remain conditional.");
        window(c, 0x1b22, 0x1b59, "record_allocator_partition", "R206: current063C size, not producer's literal12. Local no-growth zero/fill/decrement fields withCLD and returned oldDI; growth/error boundaries open. LastCALL6450 is not aRET or proved nonreturn; no closed function ABI.", monitor);
        window(c, 0x1b59, 0x1bba, "publish_record_vector_partition", "R206/R212: bound name saves full record offset then current control0A6A/LES+2, finite cursor+2, fullAX store1BA7 before localDI>>1 at01FA. Ends after errorCALL, not a complete returning function. Bank-local slot is not proved equal to resolverBX-1+06DA.", monitor);
        window(c, 0x401e, 0x4064, "select_vector_record", "R206/R212 partial resolver: finiteBX-1+current06DA; below7FC0 uses0A68, else one subtract/current0A70 then doubled offset. Full record handle selects0938 bank; current fields/guards remain. No append-slot/module identity or universal bounds.", monitor);
        window(c, 0x40b8, 0x40ef, "association_consumer", "R198: current record flags20 selects word2→CX/BX=FFFD and jumps43AA without ordinary dispatcher/FAR rewrite. Consumer NameBoundRecord15Partial/Association12Partial domains are distinct.", monitor);
        window(c, 0x67ba, 0x67d2, "initialize_vector_pair_fields", "R212 partial initializer:0A66/0A6E=0,0A6A/0A72=0A64; selectors at descriptor+4 are consumer0A68/0A70. Lifetime/slot identity remains open.", monitor);
        function(c, 0x6649, 0x6663, "allocate_vector_descriptor", "R212: capacity80/cursor0 then FAR3:000C boundary; localDI/CX saves do not prove external cleanup/selector write/allocation success.");
        function(c, 0x6663, 0x6673, "allocate_vector_pair", "R212: allocate/fill descriptor then DI+=8 and repeat. Paired layout is not successful allocation proof.");
        function(c, 0x6673, 0x6684, "fill_vector_descriptor", "R212: currentES descriptor+4, capacity/2 wordsFFFF with currentDF, noCLD; restoresDI, not AX/CX/ES.");
        function(c, 0x64ef, 0x654d, "advance_vector_bank_cf", "R212: preservesSI only under ordinary stack premises; finite remaining-space/request, compares descriptor+6+8, can publish0A6A=0A6C. Direct success returns currentES/DI, not preserved incoming pointer; clearDF/even extents are premises for word-slot projection.");
        function(c, 0xbcdd, 0xbeaf, "construct_output_header", "R162: workingDS085F, NOT inputFILE10C0. StoresNE05/0A fields;+22=40 then finite count/table shifts and selected carry checks. Optional count replacement/decrement occurs after initial<=FE check; equal+24/+26 does not prove resource absence/ownership. Helpers and diagnostic-return fallthrough remain conditional.");
        function(c, 0xab57, 0xab98, "produce_alignment_state", "R162: current001E0 gives exponent4/maskF; otherwise01A6 nonzero produces floor-log2. Input1 exponent0 executes65536 SHL iterations and maskFFFF, NOT mask0. Zero diagnostic and unsupported inputs/lifetime unresolved.");
        function(c, 0xbeaf, 0xbee1, "request_current_header_copy", "R162/R181: BC75, then86BD, THEN reloadCX40/SI085F/AX=currentB7A2/DX0 forBEDD→9E96. Prior record copies can reach external preparation first; not immutable header or physical output.");
        function(c, 0xbee1, 0xc02f, "produce_segment_record8", "R169: ordered zero/full/clipped length/allocation/sector stores to08AB/08AD/08B1; finite bytecarry/shift geometry, count0 executes65536 shifts. Current signed-kind and+13 bit tests store08AF flags last. Ordinary helper-free epilogue restores incomingAX/BX/CX/DX/DI; ES descriptor view, flags clobbered. Diagnostic tails not proved returning/preserving.");
        function(c, 0xc02f, 0xc062, "request_segment_table_records", "R162/R169: current header+22/0881+B7A2 position; descriptors advance14. Nonempty+0D OR+0F callsBEE1 thenCX8/SI08AB/DX0→9E96. BEE1 ordinary return restores inputAX; later position is actual post9E96 value. Not full count/loop/file validity.");
        function(c, 0x86bd, 0x87d8, "produce_nb02_working_records", "R181/R187: conditional clearDF initial16 NB02+12FF at08BB; saveQ from ACTUAL post-first-copyDX:AX. Selected middle0686 stores52FB/0310-or0209/current0182 and adjustedQ fields; fresh state then final08CB NB02+u32(W-Q+18). Requests9E96 at8718/8784/87CF; zero-count middle request is not a no-op. FinalDX0, actualAX; no localCLD or direct seed of0ABC/0CBD/0631/0633. Shapes are not usable debug symbols, removed-debug proof or witnessed physicalEOF.");
        function(c, 0xab98, 0xabb0, "divide_position_0200", "R181: ordinaryDIV domainDX<0200, remainder064A and wrapped rounded quotient064C; AX/BX/DX saved/restored, flags not. Overflow before stores andFFFF+carry wrap forbid unrestricted ceiling arithmetic.");
        function(c, 0x4c31, 0x4c8b, "request_current_working_record", "R198/R220: old descriptor+11 read BEFORE increment;6D01 uses old count. Fresh descriptor+8/+0A then05A4; ADC CL,CH discards byteoverflow; fresh05A6/05A8 selects source/count for4C81→9E96. Ordinary six saved registers restored, ES not preserved, CF not deliberate success.");
        function(c, 0x6d01, 0x6d19, "adjust_quantity", "R220: finiteoldDX<<1; if current001E nonzero shift twice more+2; AX addition's CF alone becomesDX0/1 via MOV/ADC. No source/count stores, helpers or external output.");
        window(c, 0x97af, 0x97d3, "select_working_source_count", "R220 partial initializer: current001E nonzero stores05A6=8/05A8=08B3 thencallsBAEF; zero selects2/0822. This is not a proved lifetime to later4C79/4C7D.", monitor);
        window(c, 0xb8f4, 0xb9e7, "working_fixup_partition", "R198 complete containing partition, selected IMPORTED branch semantics only. DH04/14→source_type5;04 alone sets08B4 bit04 and skips localFFFF source-word replacement. Ordered current08B7/08B9/058E/08B5 reads/stores then4C31; other contained bytes only boundaries, not nonimport closure.", monitor);
        function(c, 0x9e96, 0x9edf, "copy_mapped_buffer", "R162/R175/R220: map via9D26 before each chunk; capacity8000-DI. Actual ADD AX,count / ADC DL,DH, not ADC DX,0. SHR/REP MOVSW/RCL/REP MOVSB words then oddbyte with currentDF, noCLD. Conditional0633 high-water update; ordinary savedBX/CX restored andES=CS, not preserved inputES. No successful preparation/physical I/O implied.");
        window(c, 0x9d26, 0x9dbe, "map_buffer_partition", "R175: complete selected partition, not sole routine entry. SUB/SBB current0CBD; DI=lo&7FFF; BX=ROL16(hi|(lo&8000),2), not arbitrary division. No-borrow/below0200/no-diagnostic/no-preparation valid-LAR-bit path selectsES/current0ABC table and restoresAX/CX/DX, givespositive capacity. Other paths/selector validity/arguments/services unresolved.", monitor);
        function(c, 0x9ce2, 0x9d07, "prepare_table_entry_boundary", "R175: forwards words through FAR3:00E3/00ED. LocalBX saves require actual external argument disposal. DI/SI/DS/DF not locally preserved; no allocator success or identity inferred.");
        function(c, 0x9bd6, 0x9c15, "submit_current_mapped_source_count", "R256: finiteSI shift/exchanges form first4200 numeric request viaABB0. THEN fresh002A handle, currentSI/0631/0633 count, restoredAX and current0ABC+SI selector supplyABD3 sourceDS:0. No countclamp; savedDS/DX/CX restored only on intact ordinary completion, BX requires currentSI preserved; AX/ES/flags not restored.");
        window(c, 0x9c15, 0x9cae, "output_loop_slice", "R256 partial loop: branches outside9CAE. Slot tests and currentreturnedAX gates distinguish9BD6 submissions; fresh0631 loop comparison, finite wrap/control mutations remain. No physical-output or universal bounded-loop claim.", monitor);
        window(c, 0xabb0, 0xabea, "numeric_wrapper_entries", "R256/R276 multi-entry partition, not one ordinary function. ABB1 INT21; savesBX/CLD; errorDDFE consumes index9/count2/savedAX and conditionally resumesABC4. ABD3 AH40 path compares actualreturnedAX with actualcurrentCX; mismatch index7/count0 conditionally resumesABE9. No numeric-service API identity, success, nonreturn or bounded-recursion guarantee.", monitor);
        inlineReturns(c, monitor);
        farSlotFunctions(c);
        log.appendMsg(ID, "Applied exact5.1 writer/family/control/association/vector, selected output/NB02 working records, numeric boundaries, seven conditional inline returns and static FAR-slot provenance. No historical C/tool attribution, resolved dynamic service/code alias, complete debug importer or physical-I/O success inferred.");
    }

    private StructureDataType partial(String name, int length, String description) {
        StructureDataType type = new StructureDataType(TYPES, name, length);
        type.setDescription(description + " Partial descriptive analysis view; unknown bytes remain undefined. Current DS/ES/SS views, valid extents, lifetime and non-destructive aliases are prerequisites, not inferred file mappings or historical C.");
        return type;
    }

    private void word(StructureDataType type, int offset, String name, String qualification) {
        type.replaceAtOffset(offset, WORD, 2, name, qualification);
    }

    private void byteField(StructureDataType type, int offset, String name, String qualification) {
        type.replaceAtOffset(offset, BYTE, 1, name, qualification);
    }

    private DataType resolve(Context c, DataType type) {
        return c.program().getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void types(Context c) {
        StructureDataType info = partial("SegmentInfo10Partial", 10, "K2: current09B8-selected I array, distinct from matching-offset R and descriptor D. Module coordinate06D8+10*(index-1).");
        word(info, 0, "name_handle", "Interned full length/name comparison, not hash alone.");
        word(info, 2, "class_handle", "Dispatcher compares against current05F6/@OVYDATA handle.");
        word(info, 6, "length_low", "SEGDEF reader store.");
        byteField(info, 8, "length_extension", "Keep distinct from attributes at9; no unrestricted32-bit length promise.");
        byteField(info, 9, "attributes", "Raw alignmentE0/combine1C.");
        resolve(c, info);
        StructureDataType associated = partial("AssociatedEntry10Partial", 10, "K2: current09C0-selected R array; offsets match I, not descriptor numbers.");
        word(associated, 0, "descriptor_offset", "Writer first reads this field; group/absolute alternatives differ.");
        word(associated, 2, "family_entry_offset", "7D2D currentSI or7D62 rememberedCX; selected target resolver reads40DF.");
        resolve(c, associated);
        StructureDataType descriptor = partial("Descriptor20Partial", 20, "K2/R169/R220: current09D8-selected D; representative, counter, coordinate and quantity domains are distinct.");
        byteField(descriptor, 1, "kind", "Writer accepts1/3; BEE1 independently tests4 and signed<=0.");
        word(descriptor, 2, "association", "Constructor81E0.");
        word(descriptor, 4, "representative_entry_offset", "7F43 currentSI, distinct from+6; ordinary nonempty reuse preserves it.");
        word(descriptor, 6, "descriptor_number", "Separately incremented087B, not physicalCS.");
        word(descriptor, 8, "coordinate_low", "R220 fresh read after6D01.");
        byteField(descriptor, 0xa, "coordinate_extension", "ADC into CL/DL discards byte overflow.");
        word(descriptor, 0xd, "length_word", "BEE1 saves only this word, not+0F as high length.");
        word(descriptor, 0xf, "auxiliary_length_word", "C02F tests+0D OR+0F.");
        word(descriptor, 0x11, "working_count", "4C4A reads OLD value before4C4E increments.");
        byteField(descriptor, 0x13, "output_control_bits", "BEE1 reads current bits0..5 individually.");
        resolve(c, descriptor);
        StructureDataType association = partial("Association12Partial", 12, "R206: six word DS089F copy; DF is not locally cleared and this is not atomic/overlap-safe copying.");
        for (int offset = 0; offset < 12; offset += 2) {
            word(association, offset, offset == 8 ? "name_handle" : "word" + Integer.toHexString(offset), offset == 8 ? "Current08A7, bank08D8 uses low3 bits while retaining full offset." : "Current source at DS:" + Integer.toHexString(0x89f + offset) + "; earlier caller values need not remain live.");
        }
        resolve(c, association);
        StructureDataType record = partial("NameBoundRecord15Partial", 15, "R206: current0938 bank; new path assigns20, replacement requires current10 then sets20/clears10.");
        word(record, 0, "link_or_unresolved", "New record0; consumer separately rejectsFFFF.");
        word(record, 2, "association_offset", "Bit20 consumer returns this full word inCX; allocator success/extent not assumed.");
        word(record, 8, "word08", "Selected allocator decrements after clearing.");
        word(record, 0xa, "word0a", "Selected allocator decrements after clearing.");
        word(record, 0xc, "name_handle", "New producer stores currentBX; consumer loads into028A.");
        byteField(record, 0xe, "flags", "Independent10/20 controls; not exclusive tags.");
        resolve(c, record);
        StructureDataType vector = partial("VectorDescriptor8Partial", 8, "R212: paired0A64/0A6C descriptors. Selector fields0A68/0A70 correspond conditionally to resolver banks, not proof of append-slot/module identity.");
        word(vector, 0, "capacity_bytes", "Current finite ceilingFF80; consumer threshold7FC0 words.");
        word(vector, 2, "cursor_offset", "LES descriptor+2 reads current cursor and selector.");
        word(vector, 4, "selector", "External allocation/write/extent unresolved, not a file pointer.");
        word(vector, 6, "current_or_boundary_descriptor", "Initial0A64; advancement can store0A6C into0A6A.");
        resolve(c, vector);
        StructureDataType fixup = partial("FixupWorking8", 8, "R198/R220 currentDS08B3, selected initial source/count8/08B3; no proved lifetime from initializer to copier.");
        byteField(fixup, 0, "source_type", "MaskedDH04/14 both produce5.");
        byteField(fixup, 1, "flags", "OnlyDH04 sets04 and skips local source-wordFFFF replacement.");
        word(fixup, 2, "adjusted_coordinate", "u16(DI+fresh058E).");
        word(fixup, 4, "target_word", "CurrentBX at B9AB.");
        word(fixup, 6, "target_quantity", "CurrentCX at B9AF.");
        resolve(c, fixup);
        StructureDataType header = partial("OutputHeader64Partial", 64, "R162: mutable workingDS085F header, NOT the input image header at FILE10C0; not every byte is initialized by BCDD.");
        word(header, 0, "signature_ne", "BCDD stores454E.");
        byteField(header, 2, "field02", "05, not historical tool identity.");
        byteField(header, 3, "field03", "0A.");
        for (int offset : new int[] { 4, 6, 0x14, 0x16, 0x1c, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x32, 0x34 }) {
            word(header, offset, "word" + Integer.toHexString(offset), offset == 0x22 ? "0040 position; C02F adds currentB7A2. Positions+24/+26 equal does not prove resource ownership/absence." : "Current field; finite arithmetic, helper effects and partial stores qualify its interpretation.");
        }
        byteField(header, 0x36, "field36", "D976 returnedAL.");
        resolve(c, header);
        StructureDataType segment = partial("OutputSegmentRecord8", 8, "R169 mutableDS08AB; ordered geometry/flag stores, nominal eight-byte structural shape only, not full NE validity.");
        word(segment, 0, "sector_word", "Can be zero; current0891 shift loop executes65536 times for count0.");
        word(segment, 2, "raw_length", "Zero/full/clipped finite store, not proof of65536 processed bytes.");
        word(segment, 4, "flags", "Current descriptor reads; signed kind test and bit tests kept distinct.");
        word(segment, 6, "raw_allocation", "Saved descriptor+0D.");
        resolve(c, segment);
        StructureDataType initial = partial("Nb02InitialWorking16", 16, "R181 DS08BB, conditional clearDF stores; recognition shape is not a debug importer.");
        initial.replaceAtOffset(0, new ArrayDataType(BYTE, 4, 1), 4, "signature_nb02", "Stores424E/3230.");
        initial.replaceAtOffset(4, new ArrayDataType(WORD, 6, 2), 12, "ffff_words", "SixFFFF words under clearDF.");
        resolve(c, initial);
        StructureDataType footer = partial("Nb02TerminalWorking8", 8, "R181 DS08CB, distinct from initial record; conditional copy8 atW, not proof of physical EOF.");
        footer.replaceAtOffset(0, new ArrayDataType(BYTE, 4, 1), 4, "signature_nb02", "Stores424E/3230.");
        footer.replaceAtOffset(4, UnsignedIntegerDataType.dataType, 4, "finite_distance", "u32(W-Q+18h), Q saved AFTER optional first copy.");
        resolve(c, footer);
        StructureDataType middle = partial("MiddleWorkingRecordPartial", 0x30, "R181 DS0686 selected fields only; count can be u16(30+current06B4), not this fixed view's length.");
        word(middle, 0, "word52fb", null);
        word(middle, 2, "version_word", "0310 or current018F==1 selects0209.");
        word(middle, 0x20, "position_low", "Actual saved post-copyQ plus current selected adjustment.");
        word(middle, 0x22, "position_high", null);
        byteField(middle, 0x28, "control0182", "Fresh current value.");
        resolve(c, middle);
        StructureDataType slot = partial("StoredFarSlot5", 5, "R236 raw NE3 slot, not automatically executable/callable;97 EA slots and8 FF-leading positions.");
        byteField(slot, 0, "leading_byte", "Writer does not patch this byte.");
        word(slot, 1, "target_offset", "Stored relocation initially targets common trap; conditional startup writer may replace.");
        word(slot, 3, "target_selector", "Native relocation is not witnessed runtime service resolution/code alias.");
        resolve(c, slot);
        EnumDataType location = new EnumDataType(TYPES, "MaskedLocationClass", 1);
        location.add("word_offset", 4);
        location.add("far_candidate", 0xc);
        location.add("alternate_import_offset", 0x14);
        location.setDescription("DH&1C numeric classes.04/14 share working source-type5 but only04 sets local flag04. Not an exclusive descriptor-kind/record-tag domain or formal OMF identity.");
        resolve(c, location);
    }

    private Function function(Context c, int start, int end, String name, String qualification) throws Exception {
        return c.function(CODE_FILE + start, CODE_FILE + end, "tlink51_" + name, 0, qualification);
    }

    private void writerAndFamilies(Context c, TaskMonitor monitor) throws Exception {
        c.data(CODE_FILE + 0x3d08, new ArrayDataType(WORD, 8, 2));
        c.label(CODE_FILE + 0x3d08, "tlink51_location_dispatch_words8");
        for (int i = 0; i < 8; i++) {
            long cell = CODE_FILE + 0x3d08 + 2L * i;
            int target = Byte.toUnsignedInt(c.original().getOriginalByte(cell)) | (Byte.toUnsignedInt(c.original().getOriginalByte(cell + 1)) << 8);
            reference(c, cell, CODE_FILE + target, RefType.DATA);
        }
        c.comment(CODE_FILE + 0x3c2b, "Descriptor20Partial representative+4 comparison uses currentBX, not descriptor_number+6. Dynamic arrays are not assigned static FileBytes storage.");
        c.comment(CODE_FILE + 0x7f43, "Descriptor20Partial+4=currentSI; separate7F4E word+6 receives incremented087B.");
    }

    private void controlsAndAssociations(Context c, TaskMonitor monitor) throws Exception {
        c.data(CODE_FILE + 0x09a1, new ArrayDataType(BYTE, 128, 1));
        c.label(CODE_FILE + 0x09a1, "tlink51_ascii_option_classes128");
        c.comment(CODE_FILE + 0x09a1, "R126 ASCII table128, no high-bit index guard. f/F class2, +/-class1; table classification is distinct from raw-letter dispatch. Adjacent0A21..0A2B literal tlink.cfg includesNUL.");
        c.data(CODE_FILE + 0x0a21, new ArrayDataType(CharDataType.dataType, 10, 1));
        c.label(CODE_FILE + 0x0a21, "tlink51_config_candidate_name");
        c.comment(CODE_FILE + 0xd927, "NameBoundRecord15Partial+2 receives saved Association12Partial offset; D92F then ASSIGNS flags20. Existing-record D961 replaces+2 only after currentflags10 test, then OR20/AND EF; separate name/record bank domains.");
        c.farReference(CODE_FILE + 0x665c, 3, 0x000c, SLOT_FILE + 0x000c);
    }

    private void outputRecords(Context c, TaskMonitor monitor) throws Exception {
        c.label(CODE_FILE + 0xabd3, "tlink51_numeric_count_checked_entry");
        c.comment(CODE_FILE + 0xbee7, "R169 saves incomingAX, ordinaryC012..C01A restores it BEFORE consumerC051/C059. Diagnostic routes do not establish this preservation.");
        c.comment(CODE_FILE + 0x4c46, "Descriptor20Partial+0D read, then OLD+11 read at4C4A BEFORE increment4C4E. Fresh coordinate+08/+0A follows6D01; source/count05A8/05A6 freshly read later. Field views are not an immutable descriptor snapshot.");
        c.comment(CODE_FILE + 0xbf4a, "OutputSegmentRecord8: allocation+6 store08B1 precedes length+2 store08AD on this full-length branch. Other branches differ; sector+0 and current flags+4 are stored later. These are native working-buffer stores, not witnessed file bytes.");
        c.comment(CODE_FILE + 0x871b, "R181 post-first-copy currentDX:AX isQ; not the computed pre-copy position. Nb02InitialWorking16 and Nb02TerminalWorking8 are distinct views.");
        for (int call : new int[] { 0x9cf3, 0x9d00, 0x9d70, 0x9da3, 0x9c22, 0x9c3d, 0x9c67, 0x9c78, 0x9c94, 0x9ca8 }) {
            int target = switch (call) {
                case 0x9cf3 -> 0xe3;
                case 0x9d00 -> 0xed;
                case 0x9da3 -> 0xc;
                case 0x9c67 -> 0x1ce;
                case 0x9c94, 0x9ca8 -> 0x16;
                default -> 0xbb;
            };
            c.farReference(CODE_FILE + call + 1, 3, target, SLOT_FILE + target);
        }
    }

    private void prepareInlineData(Context c) throws Exception {
        for (int[] join : INLINE_TEXT_JOINS) {
            int length = join[2] - join[1] - 1;
            if (Byte.toUnsignedInt(c.original().getOriginalByte(CODE_FILE + join[1])) != length) {
                throw new IllegalStateException(ID + " inline text length disagrees with exact bytes");
            }
            StructureDataType text = new StructureDataType(TYPES, "InlineText" + length, 0);
            text.add(BYTE, "length", "Prefix is data, not an instruction.");
            text.add(new ArrayDataType(CharDataType.dataType, length, 1), "text", "No terminatingNUL; conditional clearDF resume follows exactly these bytes.");
            c.data(CODE_FILE + join[1], resolve(c, text));
            c.label(CODE_FILE + join[1], "tlink51_inline_text_" + Integer.toHexString(join[1]));
        }
        c.data(0x12800 + 0xa7d, WORD);
        c.data(0x12800 + 0xa81, WORD);
        c.data(0x12800 + 0xab, new ArrayDataType(CharDataType.dataType, 24, 1));
        c.data(0x12800 + 0xd2, new ArrayDataType(CharDataType.dataType, 18, 1));
    }

    private void inlineReturns(Context c, TaskMonitor monitor) throws Exception {
        function(c, 0xb49f, 0xb4c5, "copy_length_text", "R276: savesAX/CX, swapsDS/ES, LODS length, zeroextends and copies bytes. No localCLD; cancallB3D0. ForwardSI/resume requiresDF0/valid extents/intactviews/returning non-destructive helpers; no generic string/ABI guarantee.");
        function(c, 0xb4f0, 0xb4f8, "consume_return_inline_text", "R276: POP SI consumes nearreturn, ES=CS, CALL B49F thenJMP SI. Does NOT RET into adjacent inline text. Seven qualified calls receive conditional explicit fallthroughs to text-end; no ordinary noreturn.");
        int[][] intervals = { {0xddf9,0xde2f}, {0xde37,0xde42}, {0xde4c,0xde51}, {0xde59,0xdeb5}, {0xdec7,0xded4}, {0xdee0,0xdeec}, {0xdef1,0xdf00}, {0xdf1c,0xdf70} };
        AddressSet code = new AddressSet();
        for (int[] interval : intervals) {
            window(c, interval[0], interval[1], "error_code_" + Integer.toHexString(interval[0]), "R276 exact code-only partition; neighboring length-prefixed text is DATA. Multipleentry, consumed-return frame and conditional helper/request effects; no ordinary noreturn.", monitor);
            code.add(c.range(CODE_FILE + interval[0], CODE_FILE + interval[1]));
        }
        var manager = c.program().getFunctionManager();
        var existing = manager.getFunctionsOverlapping(code);
        while (existing.hasNext()) {
            var function = existing.next();
            if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || function.getSymbol().getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                throw new IllegalStateException(ID + " preserving higher-priority error function " + function.getEntryPoint());
            }
            manager.removeFunction(function.getEntryPoint());
        }
        Function shared = manager.createFunction("tlink51_argument_consuming_error_entries", c.mapped(CODE_FILE + 0xddf9), code, SourceType.ANALYSIS);
        shared.setStackPurgeSize(Function.UNKNOWN_STACK_DEPTH_CHANGE);
        shared.setComment("R276 shared alternative entriesDDF9/DDFE/DE03/DE08 selectAX2/4/1/0, POP returnDX beforeBP frame: indexBP+2/countBP+4/bytesBP+6. Code-only NONCONTIGUOUS body excludes all89 inline-data bytes and separateDF70 entry. If DF5A reached with intact saves, restoreDI/SI/BX/DS; savedreturn→DX; SP/AX=u16(BP+6+CURRENT count); restoreBP;PUSH DX/RET. For preCALLSP=S, finalSP=u16(S+4+n). AX/DX are not preserved interrupt results; CX/ES/flags not promised. Kind4 requests further opaque/numeric operations; actual return/termination/recursion remains unresolved. Unknown stack purge, NOT an ordinary noreturn or historical C prototype.");
        for (int entry : new int[] { 0xddfe, 0xde03, 0xde08 }) {
            c.label(CODE_FILE + entry, "tlink51_error_entry_" + Integer.toHexString(entry));
        }
        for (int[] join : INLINE_TEXT_JOINS) {
            var call = c.program().getListing().getInstructionAt(c.mapped(CODE_FILE + join[0]));
            if (call == null || !call.getFlowType().isCall() || call.getDefaultFlows().length != 1 || !call.getDefaultFlows()[0].equals(c.mapped(CODE_FILE + 0xb4f0))) {
                throw new IllegalStateException(ID + " missing actual inline helper CALL at " + Integer.toHexString(join[0]));
            }
            call.setFallThrough(c.mapped(CODE_FILE + join[2]));
            reference(c, CODE_FILE + join[0], CODE_FILE + join[1], RefType.DATA);
            c.comment(CODE_FILE + join[0], "R276 CALL B4F0 consumes its return into inline length-prefixed DATA. Conditional clearDF/intactviews/returninghelpers resume at1:" + Integer.toHexString(join[2]) + ", modeled by native fallthrough override. SetDF/helper mutation/nonreturn invalidates this path; not an unconditional return guarantee.");
        }
        c.comment(CODE_FILE + 0xdf5a, "R276 conditional rebuilt return; count freshly reread atBP+4, SP/AX=u16(BP+6+count), DX savedreturn. Kind4/helper/INT effects remain unresolved; not conventional argument cleanup or error-result preservation.");
        c.function(CODE_FILE + 0xdd30, CODE_FILE + 0xdddc, "tlink51_consumed_near_frame_formatter", Function.UNKNOWN_STACK_DEPTH_CHANGE, "R276: POP nearreturn offset and precedingCS beforeBP frame; reconstructs FAR return. Initial argument cursorBP+10; selected%d consumes2, literal disk-full string consumesnone. String termination/views/DF/numeric helper effects remain conditional, not general formatting or historicalC ABI.");
        c.function(CODE_FILE + 0xdddc, CODE_FILE + 0xddf9, "tlink51_select_message_word", 2, "R276: finite doubled index, additive selector relocationDDE2 associates currentES withNE4:0A6F; table index7/9 select tool diagnostic strings, not service contracts.");
        var selectorSource = c.mapped(CODE_FILE + 0xdde2);
        boolean selected = c.program().getRelocationTable().getRelocations(selectorSource).stream().anyMatch(r -> r.getStatus() == Relocation.Status.APPLIED && r.getType() == 2 && r.getValues().length == 5 && r.getValues()[1] == 4 && r.getValues()[3] == 4);
        var table = c.mapped(0x12800 + 0xa6f);
        int selector = Short.toUnsignedInt(c.program().getMemory().getShort(selectorSource));
        if (!selected || !((SegmentedAddressSpace) table.getAddressSpace()).getAddress(selector, 0xa6f).equals(table)) {
            throw new IllegalStateException(ID + " selected native message-selector/file-table join disagrees");
        }
        reference(c, CODE_FILE + 0xdde5, 0x12800 + 0xa6f, RefType.DATA);
        reference(c, 0x12800 + 0xa7d, 0x12800 + 0xab, RefType.DATA);
        reference(c, 0x12800 + 0xa81, 0x12800 + 0xd2, RefType.DATA);
        function(c, 0x9b20, 0x9b3d, "conditional_error_request_chain", "R276: B496/B3D0/A9A3 then forwards frameword toA9B4. These can reach/reenter numeric wrapper; actual return/termination and physical effects remain unresolved.");
        function(c, 0xa9a3, 0xa9b4, "request_current_handles", "R276: current0028/002A handles call existingABC4 continuation, NOT ABB0 interrupt entry. Actual currentBX guards/recursive returns remain conditional.");
        function(c, 0xa9b4, 0xa9db, "forward_error_request_word", "R276: current0194/019A pointer conditionalA9DB then frameword forwardedA9ED; no guaranteed external effects.");
        c.function(CODE_FILE + 0xa9db, CODE_FILE + 0xa9ed, "tlink51_numeric_request_41", 4, "R276: numericINT21 AH41 andRET4, not assigned API identity or external success.");
        c.function(CODE_FILE + 0xa9ed, CODE_FILE + 0xaa1d, "tlink51_numeric_request_4c", 2, "R276: calls01F9/009A and FARNE10:0037, then reloads framewordAX, setsAH4C andINT21. Selectedkind4 can submitAL2 under stated returning-frame premises; finalPOP BP/RET2 only IF interruptreturns. Not ordinarynoreturn/termination/exit-status proof.");
    }

    private void farSlotFunctions(Context c) throws Exception {
        for (int entry : new int[] { 0xc, 0x16, 0xbb, 0xe3, 0xed, 0x1ce }) {
            var range = c.range(SLOT_FILE + entry, SLOT_FILE + entry + 5);
            c.program().getListing().clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
            c.function(SLOT_FILE + entry, SLOT_FILE + entry + 5, "tlink51_stored_far_jump_" + Integer.toHexString(entry), Function.UNKNOWN_STACK_DEPTH_CHANGE, "R175/R236/R256 actual selected caller target; complete storedEA+relocated4-byte target, initially commontrap3:0AFC. Conditional startup patch may change words, not leadingbyte; runtime callee/cleanup/preservation/service/selectorcodealias remain unknown.");
            c.farReference(SLOT_FILE + entry + 1, 3, 0xafc, SLOT_FILE + 0xafc);
        }
        c.function(SLOT_FILE + 0xafc, SLOT_FILE + 0xb1a, "tlink51_common_numeric_trap", Function.UNKNOWN_STACK_DEPTH_CHANGE, "R175/R236: complete30-byte/18-instruction trap with selector fixupsNE12/13, numericINT21 thenINT3/INT00 and possible plainLRET. NO six-byte argument cleanup or proved returning descriptor constructor/API/physical service.");
        c.function(SLOT_FILE + 0x469, SLOT_FILE + 0x4e7, "tlink51_conditional_far_target_writer", Function.UNKNOWN_STACK_DEPTH_CHANGE, "R236: numericINT2F FB42 requests. Stores current returnedBX→ES:[DI+1], thenAX→[DI+3] only on returnedDX0. InitialCX from current0019 loaded once;04DE backedge04C3 does NOT reloadCX/ES/DI. Iteration savesAX/BX/DX only. Suitable unchanged progression covers105 positions, not105 returning calls; request3 hits000C only IF selectedES aliasescode. Final localLRET doesn't prove external service/argument contract.");
        c.comment(SLOT_FILE + 0x4de, "R236 actual04DE→04C3; noCXreload. Selected companion IRET restoresflags from interrupt frame, not necessarily localCF/CLD. Unknown callback/currentrecord/selector validity/codealias and failed-ordinal lookup may still reportDX0; service success/callable target is not established.");
    }

    private void farSlots(Context c, TaskMonitor monitor) throws Exception {
        DataType slotType = c.program().getDataTypeManager().getDataType(TYPES, "StoredFarSlot5");
        int ea = 0;
        int ff = 0;
        for (int i = 0; i < 105; i++) {
            monitor.checkCancelled();
            long cell = SLOT_FILE + 2 + 5L * i;
            int first = Byte.toUnsignedInt(c.original().getOriginalByte(cell));
            c.data(cell, slotType);
            if (first == 0xea) {
                ea++;
                c.farReference(cell + 1, 3, 0xafc, SLOT_FILE + 0xafc);
            }
            else if (first == 0xff) {
                ff++;
            }
            else {
                throw new IllegalStateException(ID + " unexpected raw slot leading byte");
            }
        }
        if (ea != 97 || ff != 8) {
            throw new IllegalStateException(ID + " raw105-slot partition differs");
        }
        c.label(SLOT_FILE + 2, "tlink51_stored_far_slots105");
        c.comment(SLOT_FILE + 2, "R236:525 raw bytes/105 five-byte positions,97 EA stored FAR jumps and8 FF-leading nonjump positions; NOT105 executable stubs. Original applied relocations join97 target words to common3:0AFC trap. Conditional runtime writer changes target words only IF returnedES aliases code and services/currentregisters/saves qualify; native static relocation is not witnessed loadedpatch/service resolution.");

    }

    private void reference(Context c, long source, long target, RefType type) {
        c.program().getReferenceManager().addMemoryReference(c.mapped(source), c.mapped(target), type, SourceType.ANALYSIS, 0);
    }

    private void window(Context c, int start, int end, String name, String qualification, TaskMonitor monitor) throws Exception {
        var range = c.range(CODE_FILE + start, CODE_FILE + end);
        var cursor = range.getMinAddress();
        while (cursor.compareTo(range.getMaxAddress()) <= 0) {
            monitor.checkCancelled();
            var command = new DisassembleCommand(cursor, range, false);
            command.enableCodeAnalysis(false);
            command.applyTo(c.program(), monitor);
            var instruction = c.program().getListing().getInstructionAt(cursor);
            if (instruction == null || instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0) {
                throw new IllegalStateException(ID + " incomplete qualified code partition at " + cursor);
            }
            cursor = cursor.add(instruction.getLength());
        }
        c.label(CODE_FILE + start, "tlink51_" + name);
        c.comment(CODE_FILE + start, qualification + " Original NE1 offsets, FILE=1200+offset; partial/multi-entry partitions do not imply a containing function or stronger ABI.");
    }
}
