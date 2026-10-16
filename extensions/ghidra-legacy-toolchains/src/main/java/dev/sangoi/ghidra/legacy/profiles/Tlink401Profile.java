package dev.sangoi.ghidra.legacy.profiles;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Independently evidenced TLINK4.01 MZ facts; no5.1 field/address transport. */
public final class Tlink401Profile extends ToolchainProfile {
    public static final String ID = "tlink401-qualified";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/TLINK401");

    public Tlink401Profile() {
        super(ID, "Old-style DOS Executable (MZ)", 73401, "df1be38b22d43cc912992f1fcca93a5b630197721744ef2eea399f22d1415f0c");
    }

    @Override
    public void prepareData(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        if (!c.program().getLanguageID().toString().equals("x86:LE:16:Real Mode")) {
            throw new IllegalStateException(ID + " requires the native16-bit MZ real-mode import");
        }
        monitor.checkCancelled();
        types(c);
        c.data(0x3546, new ArrayDataType(UnsignedShortDataType.dataType, 8, 2));
        c.label(0x3546, "tlink401_location_dispatch_words8");
        c.comment(0x3546, "R144: eight raw CS-relative word targets, not FAR pointers or unconditional calls. Slot3/location0C selects3198. Native loaded source addresses come from original FILE mappings, never an NE ordinal.");
        for (int i = 0; i < 8; i++) {
            long cell = 0x3546 + 2L * i;
            int target = Byte.toUnsignedInt(c.original().getOriginalByte(cell)) | (Byte.toUnsignedInt(c.original().getOriginalByte(cell + 1)) << 8);
            c.program().getReferenceManager().addMemoryReference(c.mapped(0x3546 + 2L * i), c.mapped(0x400L + target), RefType.DATA, SourceType.ANALYSIS, 0);
        }
        c.comment(0x72d1, "R144: selected ordinary reuse branch6ED1..6F1F; no universal equal-name iff equal-descriptor rule. I uses current0776, R current077E, D current079E.");
        c.comment(0x5ed, "R151: actual MZ relocation selects startup DS11B1 relative paragraph;11B10 is beyond initialized load-image end11AB9. DS0017 is not an initialized FileBytes object. Native relocated pointers, not FILE+inventedDS, own the loaded view; startup/helper/service/lifetime remain unproved.");
        c.comment(0x3b0f, "Actual selected near CALL370F→3058 (writer); returnedCF later overwritten by resolver37A0. See tlink401_Frame/descriptor views; no5.1 fields or option latch imported.");
    }

    @Override
    public void applyFinalFacts(Context c, TaskMonitor monitor, MessageLog log) throws Exception {
        monitor.checkCancelled();
        var writer = c.function(0x3458, 0x34ee, "tlink401_rewrite_far_window_cf", 0, "R118/R144: CS0 load-image[3058,30EE), original FILE=0400+load offset. Descriptor kind1/3 and representative word4==BX plus opcode/buffer guards are required; not final physical-segment equality. DS03E6/03E8 are current entry/record coordinates;077E/079E select distinct arrays. For j=DX&03FF, old operand is read before opcode rejection.9A→90 0E E8, EA→90 90 E9; j0 additionally checks0210/0212 and uses saved opcode0214, setting carry-back0C4C. Success adds F802 to fullDX, subtracts j/4/current03E8 fromCX, writes marker021C=FFFF and setsCF; rejectionCF0. Saved AX/SI/DI restored; finalES is descriptor view.");
        if (writer.applied()) {
            TlinkWriterContract.apply(c, writer.function(), monitor);
        }
        c.function(0x3556, 0x3622, "tlink401_location_dispatch", 0, "R144: complete3156..3222 including diagnostic backedge3220→31B2.3198 compares currentDS0450 against I[BX]+2; equality bypasses writer.31A5 calls3058 only on inequality; returnedCF1 skips30EE. No immediate5.1-style disable guard in this partition; upstream controls remain open.");
        c.function(0x6e8f, 0x702a, "tlink401_produce_entry_family", 0, "R144: current07BE list; combinable same-name entries retain remembered entry offset in R+2. Nonzero alignmentE0/combine1C and list/order/state conditions apply; producer does not itself compare class handles. OrdinaryRET6BF2, diagnostic tail through6C28 included.");
        c.function(0x70fb, 0x7127, "tlink401_allocate_descriptor20", 0, "R144: request14h via079A; successful usable allocation clears20 bytes, stores currentSI at descriptor+4, independently increments06B9 and stores number at+6. Growth/error effects unresolved; representative is not descriptor number/finalCS.");
        c.function(0x716e, 0x7559, "tlink401_construct_family_descriptor", 0, "R144: ordinary nonempty reuse requires equal name/class, nonzero combine and flag02 clear; publish existing descriptor in R+0 without replacing+4. Empty/special/packing branches differ. OrdinaryRET7100 and diagnostic tail7156→708A included; helper effects remain conditional.");
        window(c, 0x363a, 0x37a7, "frame50_selected_callers", "R144: explicitly partial363A..37A7. Selected frame50 setsBX=DI; ordinary0215 flags clear and current0017 nonzero select lowCX/high0420 SUB/SBB of021E/0220. RestoredDX class0C calls3058 at370F;37A0 recomputesDI then clearsCF, so resolver finalCF is not writerCF. No immediate rewrite-disable test, not global suppression absence.", monitor);
        window(c, 0x00ea, 0x0135, "mode_current_stores", "R151: partial startup suffix, not whole function. First0100 store0017=(current0128!=1); call9487/017F/BC2B; second0122 store0017=(current0128>=2). Intervening BC2B→A63F can change0128. Parser mode is not a lifetime guarantee.", monitor);
        window(c, 0x0574, 0x0656, "raw_option_dispatch", "R151: complete selected raw-letter dispatch partition, not complete parser. Generic savedCH has no f comparison; ordinary/f reaches0653→07A6, not5.1 disable setter. BF71 effects unresolved; no cross-release CLI equivalence.", monitor);
        window(c, 0x06fc, 0x0773, "selected_mode_option", "R151: raw uppercaseT selects handler; ordinary next folded d/w/o/b stores0128=1/2/3/4. Further modifiers and961B are conditional, not final current0017 or historical configuration.", monitor);
        window(c, 0x08a6, 0x08e9, "selected_uppercase_p_option", "R151: selected/P- clears0126 at08BE; chosen caller/writer do not read that separate byte. No global absence-of-suppression conclusion.", monitor);
        log.appendMsg(ID, "Applied independently qualified4.01 writer, table, representative/control facts. No successful4.01 production specimen,5.1-specific record transport, physical service or historical invocation claim.");
        log.appendMsg(ID, "Applied independently qualified4.01 writer, table, representative/control facts. No successful4.01 production specimen,5.1-specific record transport, physical service or historical invocation claim.");
    }

    private void types(Context c) {
        StructureDataType descriptor = new StructureDataType(TYPES, "Descriptor20Partial", 20);
        descriptor.setDescription("R144 independently demonstrated4.01 view through current079E, not a mapped initializedDS object or final output segment.");
        descriptor.replaceAtOffset(1, ByteDataType.dataType, 1, "kind", "Writer accepts1/3.");
        descriptor.replaceAtOffset(4, UnsignedShortDataType.dataType, 2, "representative_entry_offset", "6D15 currentSI; writer compares againstBX.");
        descriptor.replaceAtOffset(6, UnsignedShortDataType.dataType, 2, "descriptor_number", "Separate06B9 counter, not representative.");
        c.program().getDataTypeManager().resolve(descriptor, DataTypeConflictHandler.DEFAULT_HANDLER);
        StructureDataType entry = new StructureDataType(TYPES, "AssociatedEntry10Partial", 10);
        entry.setDescription("R144 current077E view; entry offsets are not physical selectors.");
        entry.replaceAtOffset(0, UnsignedShortDataType.dataType, 2, "descriptor_offset", "Ordinary constructor publication.");
        entry.replaceAtOffset(2, UnsignedShortDataType.dataType, 2, "family_entry_offset", "Independent producer6B09/6B3E, selected target key.");
        c.program().getDataTypeManager().resolve(entry, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private void window(Context c, int start, int end, String name, String qualification, TaskMonitor monitor) throws Exception {
        var range = c.range(0x400L + start, 0x400L + end);
        var cursor = range.getMinAddress();
        while (cursor.compareTo(range.getMaxAddress()) <= 0) {
            var command = new DisassembleCommand(cursor, range, false);
            command.enableCodeAnalysis(false);
            command.applyTo(c.program(), monitor);
            var instruction = c.program().getListing().getInstructionAt(cursor);
            if (instruction == null || instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0) {
                throw new IllegalStateException(ID + " incomplete qualified code partition at " + cursor);
            }
            cursor = cursor.add(instruction.getLength());
        }
        c.label(0x400L + start, "tlink401_" + name);
        c.comment(0x400L + start, qualification + " Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred.");
    }
}
