package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.ne.SegmentRelocation;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Annotates native NE applications; does not parse NE files, resolve selectors, or add edges. */
public class NeRelocationProvenanceAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "NE relocation provenance (qualified 16-bit)";
    public static final String MARKER = "[NE relocation provenance] ";

    public NeRelocationProvenanceAnalyzer() {
        super(NAME, "Relate native NE relocation applications, original/current fields and actual instruction operand masks without inferring runtime binding.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "New Executable (NE)".equals(program.getExecutableFormat())
            && (program.getLanguageID().toString().equals("x86:LE:16:Protected Mode")
                || program.getLanguageID().toString().equals("x86:LE:16:Real Mode"));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        var applications = program.getRelocationTable().getRelocations(set);
        Address previous = null;
        while (applications.hasNext()) {
            monitor.checkCancelled();
            Address application = applications.next().getAddress();
            if (application.equals(previous)) {
                continue;
            }
            previous = application;
            List<String> observations = new ArrayList<>();
            try {
                for (Relocation relocation : program.getRelocationTable().getRelocations(application)) {
                    observations.add(MARKER + describe(program, relocation));
                }
                replaceObservations(program, application, observations);
            }
            catch (IOException | MemoryAccessException e) {
                log.appendMsg(NAME, "Could not read native provenance at " + application + ": " + e.getMessage());
                return false;
            }
        }
        return true;
    }

    private String describe(Program program, Relocation relocation) throws IOException, MemoryAccessException {
        Address application = relocation.getAddress();
        int type = relocation.getType();
        int width = type >= 0 && type < SegmentRelocation.TYPE_LENGTHS.length ? SegmentRelocation.TYPE_LENGTHS[type] : 0;
        StringBuilder text = new StringBuilder("application=").append(application)
            .append(" type=").append(type).append(" status=").append(relocation.getStatus());
        long[] values = relocation.getValues();
        if (values == null || values.length != SegmentRelocation.VALUES_SIZE) {
            return text.append("; native NE five-value tuple unavailable; target/chain/operand unproved").toString();
        }
        int flags = (int) values[1] & 0xff;
        int targetSegment = (int) values[3] & 0xffff;
        int targetOffset = (int) values[4] & 0xffff;
        text.append(String.format(" flags=0x%02x source-native-segment=0x%04x chain-head=0x%04x; ", flags, values[0] & 0xffff, values[2] & 0xffff));
        switch (flags & SegmentRelocation.FLAG_TARGET_MASK) {
            case SegmentRelocation.FLAG_INTERNAL_REF:
                if (targetSegment == SegmentRelocation.MOVEABLE) {
                    text.append("raw-target=movable entry-ordinal=").append(targetOffset);
                }
                else {
                    text.append("raw-target=internal NE-segment-ordinal=").append(targetSegment).append(String.format(" offset=0x%04x", targetOffset));
                }
                break;
            case SegmentRelocation.FLAG_IMPORT_ORDINAL:
                text.append("raw-target=import module-index=").append(targetSegment).append(" ordinal=").append(targetOffset);
                break;
            case SegmentRelocation.FLAG_IMPORT_NAME:
                text.append("raw-target=import module-index=").append(targetSegment).append(String.format(" name-table-offset=0x%04x", targetOffset));
                break;
            default:
                text.append(String.format("raw-target=OS-fixup 0x%04x:0x%04x (unresolved)", targetSegment, targetOffset));
        }
        boolean additive = (flags & SegmentRelocation.FLAG_ADDITIVE) != 0;
        text.append("; ").append(additive ? "additive-flag" : "chained-flag (head retained separately)")
            .append("; loader-operation=").append(loaderOperation(type, additive));
        if (width == 0) {
            return text.append("; unsupported width; patched range/operand/target unproved").toString();
        }
        Address end = application.add(width - 1);
        text.append("; range=[").append(application).append(',').append(end).append("] ").append(width).append("B");
        byte[] original = originalBytes(program, application, width);
        byte[] retained = relocation.getBytes();
        byte[] current = new byte[width];
        program.getMemory().getBytes(application, current);
        text.append("; original-file=").append(hex(original)).append(" retained=").append(hex(retained)).append(" current=").append(hex(current));
        text.append("; ").append(parts(type, original, additive ? "original-raw" : "original-raw (chain storage, not loaded values)")).append(parts(type, current, "current"));
        text.append("; ").append(ownership(program, application, end));
        return text.append("; byte ownership is not pointer identity; runtime binding/whole edge unproved").toString();
    }

    // Describe the current native loader implementation, not the normative meaning of a flag.
    private String loaderOperation(int type, boolean additive) {
        return switch (type) {
            case SegmentRelocation.TYPE_LO_BYTE -> "overwrite low byte (additive arithmetic not implemented)";
            case SegmentRelocation.TYPE_SEGMENT -> "overwrite selector16 only (additive arithmetic not implemented; no complete far target)";
            case SegmentRelocation.TYPE_OFFSET -> "overwrite offset16 only (additive arithmetic not implemented; no complete far target)";
            case SegmentRelocation.TYPE_FAR_ADDR -> additive ? "add original DWORD to loaded FAR16:16 (32-bit arithmetic)" : "overwrite offset16+selector16";
            case SegmentRelocation.TYPE_FAR_ADDR_48, SegmentRelocation.TYPE_OFFSET_32 -> "not implemented by native NE loader; APPLIED status does not prove a patch";
            default -> "unsupported; patch semantics unproved";
        };
    }

    private byte[] originalBytes(Program program, Address start, int width) throws IOException {
        byte[] bytes = new byte[width];
        for (int i = 0; i < width; i++) {
            Address address = start.add(i);
            var info = program.getMemory().getAddressSourceInfo(address);
            if (info == null) {
                return null;
            }
            var source = info.getMemoryBlockSourceInfo();
            var file = source.getFileBytes();
            long offset = source.getFileBytesOffset(address);
            if (file.isEmpty() || offset < 0) {
                return null;
            }
            bytes[i] = file.get().getOriginalByte(offset);
        }
        return bytes;
    }

    private String parts(int type, byte[] bytes, String label) {
        if (bytes == null) {
            return label + "-parts=unavailable ";
        }
        return switch (type) {
            case SegmentRelocation.TYPE_FAR_ADDR -> String.format("%s offset16=0x%04x selector16=0x%04x ", label, word(bytes, 0), word(bytes, 2));
            case SegmentRelocation.TYPE_SEGMENT -> String.format("%s selector16=0x%04x (offset not relocated) ", label, word(bytes, 0));
            case SegmentRelocation.TYPE_OFFSET -> String.format("%s offset16=0x%04x (selector not relocated) ", label, word(bytes, 0));
            default -> label + "-typed-parts=unproved ";
        };
    }

    private int word(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private String hex(byte[] bytes) {
        return bytes == null ? "unavailable" : HexFormat.of().formatHex(bytes);
    }

    private String ownership(Program program, Address start, Address end) {
        Instruction instruction = program.getListing().getInstructionContaining(start);
        if (instruction == null || !instruction.contains(end)) {
            return "operand=unproved (range is not within one native instruction)";
        }
        int first = (int) start.subtract(instruction.getAddress());
        int last = (int) end.subtract(instruction.getAddress());
        int owner = -1;
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            var mask = instruction.getPrototype().getOperandValueMask(operand);
            if (mask == null) {
                // An absent operand mask cannot establish uniqueness against other operands.
                return "operand=unproved (native operand mask unavailable)";
            }
            byte[] bytes = mask.getBytes();
            boolean overlaps = false;
            boolean covers = bytes.length > last;
            for (int position = first; position <= last; position++) {
                int bits = position < bytes.length ? bytes[position] & 0xff : 0;
                overlaps |= bits != 0;
                covers &= bits == 0xff;
            }
            if (overlaps) {
                if (!covers || owner != -1) {
                    return "operand=unproved (partial or overlapping native operand masks)";
                }
                owner = operand;
            }
        }
        if (owner == -1) {
            return "operand=unproved (no native operand mask covers range)";
        }
        return "instruction=" + instruction.getAddress() + " " + instruction.getMnemonicString()
            + " operand[" + owner + "] fully covered by unique native mask; native-flow=" + instruction.getFlowType()
            + " native-targets=" + Arrays.toString(instruction.getFlows());
    }

    private void replaceObservations(Program program, Address address, List<String> observations) {
        var listing = program.getListing();
        String previous = listing.getComment(CommentType.EOL, address);
        // This reserved single-line marker owns only generated observations, never the user's prose.
        List<String> lines = new ArrayList<>();
        if (previous != null) {
            lines.addAll(Arrays.asList(previous.split("\n", -1)));
            lines.removeIf(line -> line.startsWith(MARKER));
        }
        lines.addAll(observations);
        String updated = String.join("\n", lines);
        if (!updated.equals(previous)) {
            listing.setComment(address, CommentType.EOL, updated);
        }
    }
}
