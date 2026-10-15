// Native boundary assertions for actual retained inputs, automatic analyzer output and rerun ownership.
// Arguments: original input, existing output directory, expected initial offset, footer offset (-1 if absent), distance.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import dev.sangoi.ghidra.legacy.Nb02StructureAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;

public class ValidateNb02Structure extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path original = Path.of(args[0]);
        Path output = Path.of(args[1]);
        long initial = Long.decode(args[2]);
        long footer = Long.decode(args[3]);
        long distance = Long.decode(args[4]);
        byte[] input = Files.readAllBytes(original);
        var sources = currentProgram.getMemory().getAllFileBytes();
        require(sources.size() == 1, "Expected exactly the native loader's complete original FileBytes");
        var source = sources.get(0);
        require(source.getFileOffset() == 0 && source.getSize() == input.length, "Original FileBytes must cover the complete named source, with zero base");
        byte[] retained = new byte[input.length];
        require(source.getOriginalBytes(0, retained) == retained.length && Arrays.equals(input, retained), "Every imported original byte must equal the named source, not relocated memory");
        require(initial >= 0 && initial + 16 <= input.length, "Expected initial range outside actual input");
        require(Arrays.equals(Arrays.copyOfRange(input, (int) initial, (int) initial + 16), java.util.HexFormat.of().parseHex("4e423032ffffffffffffffffffffffff")), "Actual initial-shaped bytes differ");

        Options options = currentProgram.getOptions(Program.PROGRAM_INFO);
        String key = Nb02StructureAnalyzer.OPTION_PREFIX + "0";
        String report = options.getString(key, null);
        require(report != null, "Installed production analyzer must have run automatically");
        require(report.contains("Complete 16-byte initial-shaped NB02 + twelve FF bytes at " + range(initial, 16)), "Initial-only observation missing or wrong");
        require(report.indexOf("Complete 16-byte initial-shaped") == report.lastIndexOf("Complete 16-byte initial-shaped"), "Unexpected additional complete initial observations");
        if (footer >= 0) {
            require(footer == input.length - 8 && input.length - distance == initial && initial + 16 <= footer, "Actual expected footer relation differs");
            require(Arrays.equals(Arrays.copyOfRange(input, (int) footer, (int) footer + 4), new byte[] { 0x4e, 0x42, 0x30, 0x32 }), "Actual terminal marker differs");
            long stored = Integer.toUnsignedLong(java.nio.ByteBuffer.wrap(input, (int) footer + 4, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt());
            require(stored == distance, "Actual unsigned little-endian footer distance differs");
            require(report.contains("Terminal 8-byte NB02 footer at " + range(footer, 8)) && report.contains("distance=0x" + Long.toHexString(distance)) && report.contains("Qualified physical relation"), "Footer/initial physical relation missing");
        }
        else {
            require(!Arrays.equals(Arrays.copyOfRange(input, input.length - 8, input.length - 4), new byte[] { 0x4e, 0x42, 0x30, 0x32 }), "Input unexpectedly has terminal footer marker");
            require(report.contains("No terminal NB02 footer") && !report.contains("Qualified physical relation"), "Initial-only input must not be assigned a footer relation");
        }
        require(report.contains("no symbol/type import") && report.contains("or conclusion about removed/truncated/absent debug information"), "Structural limitations must remain explicit");

        StringBuilder evidence = new StringBuilder("Ghidra ").append(getGhidraVersion()).append("\nInput ").append(original).append("\nFormat ").append(currentProgram.getExecutableFormat()).append("\nAll ").append(input.length).append(" retained original bytes equal the input.\n").append(report).append('\n');
        for (long offset : footer >= 0 ? new long[] { initial, footer } : new long[] { initial }) {
            var mappings = currentProgram.getMemory().locateAddressesForFileBytesOffset(source, offset);
            evidence.append("Native mappings for FileBytes offset 0x").append(Long.toHexString(offset)).append(": ").append(mappings).append('\n');
            for (Address address : mappings) {
                String comment = currentProgram.getListing().getComment(CommentType.PRE, address);
                require(comment != null && comment.contains("[Legacy toolchains NB02 structure]") && comment.contains("Offsets below are relative to this FileBytes object"), "Mapped native location must carry a qualified analyzer block");
            }
        }

        // Exercise rerun ownership on the actual Program without manufacturing file bytes or memory maps.
        Address userAddress = currentProgram.getMinAddress();
        String userComment = "User NB02 validation comment: keep exact whitespace.  \nsecond line";
        String originalComment = currentProgram.getListing().getComment(CommentType.PRE, userAddress);
        currentProgram.getListing().setComment(userAddress, CommentType.PRE, userComment);
        String unrelated = "NB02 validation unrelated user option";
        String previousUnrelated = options.getString(unrelated, null);
        options.setString(unrelated, "user value");
        Map<String, Object> otherOptions = new LinkedHashMap<>();
        for (String name : options.getOptionNames()) {
            if (!name.startsWith(Nb02StructureAnalyzer.OPTION_PREFIX)) {
                otherOptions.put(name, options.getObject(name, null));
            }
        }
        var beforeComments = comments();
        int blocks = currentProgram.getMemory().getBlocks().length;
        long symbols = currentProgram.getSymbolTable().getNumSymbols();
        int types = currentProgram.getDataTypeManager().getDataTypeCount(true);
        String stale = Nb02StructureAnalyzer.OPTION_PREFIX + "999";
        options.setString(stale, "obsolete analyzer-owned observation");
        options.setString(key, "obsolete analyzer-owned observation");
        Nb02StructureAnalyzer analyzer = new Nb02StructureAnalyzer();
        MessageLog log = new MessageLog();
        require(analyzer.added(currentProgram, new AddressSet(currentProgram.getMemory()), monitor, log), "Production rerun failed: " + log);
        require(report.equals(options.getString(key, null)) && !options.contains(stale), "Rerun must refresh its facts and remove stale owned observations");
        require(beforeComments.equals(comments()), "Rerun must preserve all existing comments and keep owned blocks stable");
        require(analyzer.added(currentProgram, new AddressSet(currentProgram.getMemory()), monitor, log), "Second production rerun failed: " + log);
        require(report.equals(options.getString(key, null)) && beforeComments.equals(comments()), "Unchanged second run must be stable");
        for (var entry : otherOptions.entrySet()) {
            require(Objects.equals(entry.getValue(), options.getObject(entry.getKey(), null)), "Unrelated Program option changed: " + entry.getKey());
        }
        require(blocks == currentProgram.getMemory().getBlocks().length, "Analyzer must not invent analysis memory");
        require(symbols == currentProgram.getSymbolTable().getNumSymbols() && types == currentProgram.getDataTypeManager().getDataTypeCount(true), "Structural analysis must not create symbols or types");
        currentProgram.getListing().setComment(userAddress, CommentType.PRE, originalComment);
        if (previousUnrelated == null) {
            options.removeOption(unrelated);
        }
        else {
            options.setString(unrelated, previousUnrelated);
        }
        evidence.append("Two production reruns: stable observations/comments; stale owned facts refreshed; unrelated options/comments preserved; no memory blocks, symbols or types created.\n").append(log).append('\n');
        Files.writeString(output.resolve("nb02-structure.txt"), evidence);
        println("NB02 STRUCTURE VALIDATION PASS: complete native original bytes; initial/footer distinction and arithmetic; actual mapping state; rerun ownership; no symbol/type import. " + output);
    }

    private Map<String, String> comments() {
        Map<String, String> result = new LinkedHashMap<>();
        for (CommentType type : CommentType.values()) {
            var addresses = currentProgram.getListing().getCommentAddressIterator(type, currentProgram.getMemory(), true);
            while (addresses.hasNext()) {
                Address address = addresses.next();
                result.put(type + " " + address, currentProgram.getListing().getComment(type, address));
            }
        }
        return result;
    }

    private String range(long offset, int length) {
        return "[0x" + Long.toHexString(offset) + ",0x" + Long.toHexString(offset + length) + ")";
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
