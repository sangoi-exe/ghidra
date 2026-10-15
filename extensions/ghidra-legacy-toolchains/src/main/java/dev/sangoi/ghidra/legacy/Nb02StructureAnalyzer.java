package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MzLoader;
import ghidra.app.util.opinion.NeLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Observes two demonstrated byte shapes, not a debug directory or producer execution history. */
public class Nb02StructureAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "NB02 initial/footer structure";
    public static final String OPTION_PREFIX = "Legacy toolchains NB02 structure.FileBytes ";
    private static final String COMMENT_START = "\n[Legacy toolchains NB02 structure]\n";
    private static final String COMMENT_END = "\n[/Legacy toolchains NB02 structure]";
    private static final String LIMIT = "Structural byte/arithmetic compatibility only; no symbol/type import, complete debug-directory claim, historical producer attribution, or conclusion about removed/truncated/absent debug information.";
    private static final byte[] INITIAL = {
        0x4e, 0x42, 0x30, 0x32, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    public Nb02StructureAnalyzer() {
        super(NAME, "Observe complete NB02 initial-shaped records and terminal footer arithmetic in retained original FileBytes.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        String format = program.getExecutableFormat();
        return NeLoader.NE_NAME.equals(format) || MzLoader.MZ_NAME.equals(format);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        Map<String, String> observations = new LinkedHashMap<>();
        Map<Address, List<String>> comments = new LinkedHashMap<>();
        try {
            List<FileBytes> sources = program.getMemory().getAllFileBytes();
            for (int index = 0; index < sources.size(); index++) {
                monitor.checkCancelled();
                FileBytes source = sources.get(index);
                List<Long> initials = initialOffsets(source, monitor);
                byte[] footer = new byte[8];
                boolean terminal = source.getSize() >= footer.length && source.getOriginalBytes(source.getSize() - footer.length, footer) == footer.length && footer[0] == 0x4e && footer[1] == 0x42 && footer[2] == 0x30 && footer[3] == 0x32;
                if (initials.isEmpty() && !terminal) {
                    continue;
                }
                String context = "FileBytes " + index + " (" + source.getFilename() + "), source-file base " + hex(source.getFileOffset()) + ", retained length " + hex(source.getSize()) + ". Offsets below are relative to this FileBytes object; end means its retained end, not a reconstructed source-file boundary.\n";
                StringBuilder report = new StringBuilder(context);
                for (long offset : initials) {
                    String fact = "Complete 16-byte initial-shaped NB02 + twelve FF bytes at " + range(offset, 16) + ".";
                    report.append(fact).append(" Native mappings: ").append(annotate(program, source, offset, context + fact + "\n" + LIMIT, comments)).append('\n');
                }
                if (terminal) {
                    long footerOffset = source.getSize() - 8;
                    long distance = (footer[4] & 0xffL) | ((footer[5] & 0xffL) << 8) | ((footer[6] & 0xffL) << 16) | ((footer[7] & 0xffL) << 24);
                    long target = source.getSize() - distance;
                    boolean linked = target >= 0 && target <= footerOffset - 16 && initials.contains(target);
                    String fact = "Terminal 8-byte NB02 footer at " + range(footerOffset, 8) + "; unsigned little-endian distance=" + hex(distance) + "; retained end - distance=" + (target < 0 ? "-" + hex(-target) : hex(target)) + ". "
                        + (linked ? "Qualified physical relation to the complete initial-shaped record before the footer." : "No qualified physical relation to a complete initial-shaped record before the footer.");
                    report.append(fact).append(" Native mappings: ").append(annotate(program, source, footerOffset, context + fact + "\n" + LIMIT, comments)).append('\n');
                }
                else {
                    report.append("No terminal NB02 footer at retained FileBytes end.\n");
                }
                report.append(LIMIT);
                observations.put(OPTION_PREFIX + index, report.toString());
            }
        }
        catch (IOException e) {
            log.appendMsg(NAME, "Unable to read retained original FileBytes: " + e.getMessage());
            log.appendException(e);
            return false;
        }
        monitor.checkCancelled();
        Options options = program.getOptions(Program.PROGRAM_INFO);
        for (String key : options.getOptionNames()) {
            if (key.startsWith(OPTION_PREFIX) && !observations.containsKey(key)) {
                options.removeOption(key);
            }
        }
        observations.forEach((key, value) -> {
            if (!value.equals(options.getString(key, null))) {
                options.setString(key, value);
            }
        });
        updateComments(program, comments);
        log.appendMsg(NAME, "Recorded structural observations for " + observations.size() + " retained FileBytes object(s); no debug symbols or types imported.");
        return true;
    }

    private List<Long> initialOffsets(FileBytes source, TaskMonitor monitor) throws IOException, CancelledException {
        List<Long> offsets = new ArrayList<>();
        byte[] window = new byte[65536];
        for (long start = 0; start <= source.getSize() - INITIAL.length;) {
            monitor.checkCancelled();
            int length = (int) Math.min(window.length, source.getSize() - start);
            if (source.getOriginalBytes(start, window, 0, length) != length) {
                throw new IOException("Incomplete original-byte read at " + hex(start));
            }
            for (int i = 0; i <= length - INITIAL.length; i++) {
                int j = 0;
                while (j < INITIAL.length && window[i + j] == INITIAL[j]) {
                    j++;
                }
                if (j == INITIAL.length) {
                    offsets.add(start + i);
                }
            }
            start += length - INITIAL.length + 1;
        }
        return offsets;
    }

    private List<Address> annotate(Program program, FileBytes source, long offset, String fact, Map<Address, List<String>> comments) {
        List<Address> mappings = program.getMemory().locateAddressesForFileBytesOffset(source, offset);
        for (Address address : mappings) {
            comments.computeIfAbsent(address, ignored -> new ArrayList<>()).add(fact);
        }
        return mappings;
    }

    private void updateComments(Program program, Map<Address, List<String>> comments) {
        var listing = program.getListing();
        var addresses = new LinkedHashSet<>(comments.keySet());
        var existing = listing.getCommentAddressIterator(CommentType.PRE, program.getMemory(), true);
        while (existing.hasNext()) {
            Address address = existing.next();
            String text = listing.getComment(CommentType.PRE, address);
            if (text != null && text.contains(COMMENT_START)) {
                addresses.add(address);
            }
        }
        for (Address address : addresses) {
            String previous = listing.getComment(CommentType.PRE, address);
            String text = previous == null ? "" : previous;
            int start;
            while ((start = text.indexOf(COMMENT_START)) >= 0) {
                int end = text.indexOf(COMMENT_END, start + COMMENT_START.length());
                if (end < 0) {
                    break; // Never consume user text after an incomplete marker.
                }
                text = text.substring(0, start) + text.substring(end + COMMENT_END.length());
            }
            if (comments.containsKey(address)) {
                text += COMMENT_START + String.join("\n", comments.get(address)) + COMMENT_END;
            }
            String replacement = text.isEmpty() ? null : text;
            if (!Objects.equals(previous, replacement)) {
                listing.setComment(address, CommentType.PRE, replacement);
            }
        }
    }

    private static String range(long offset, int length) {
        return "[" + hex(offset) + "," + hex(offset + length) + ")";
    }

    private static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
