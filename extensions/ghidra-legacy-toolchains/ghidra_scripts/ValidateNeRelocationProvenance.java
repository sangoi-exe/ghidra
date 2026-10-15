// Native original-file integration checks. Arguments: fresh output directory, johnny|simtower|wavmix, optional probe.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import dev.sangoi.ghidra.legacy.NeRelocationProvenanceAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.CommentType;

public class ValidateNeRelocationProvenance extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[0]);
        String corpus = args[1];
        require(new NeRelocationProvenanceAnalyzer().canAnalyze(currentProgram), "Native NE x86:16 import required");
        long[][] cases = switch (corpus) {
            // Instruction FILE offset, application FILE offset, type, raw flags.
            case "johnny" -> new long[][] { { 0xdd77, 0xdd78, 3, 0 }, { 0xdd83, 0xdd84, 3, 1 } };
            case "simtower" -> simtowerCases();
            case "wavmix" -> new long[][] { { 0x26b8, 0x26bb, 2, 0 }, { 0x226d, 0x226e, 5, 1 } };
            default -> throw new IllegalArgumentException("Unknown original corpus: " + corpus);
        };
        StringBuilder evidence = new StringBuilder("Native original static import: ").append(currentProgram.getName())
            .append("\nFormat ").append(currentProgram.getExecutableFormat()).append("\nLanguage ").append(currentProgram.getLanguageID()).append('\n');
        for (long[] selected : cases) {
            Address start = mapped(selected[0]);
            Address application = mapped(selected[1]);
            int length = selected[2] == 5 ? 3 : 5;
            DisassembleCommand command = new DisassembleCommand(start, new AddressSet(start, start.add(length - 1)), false);
            command.enableCodeAnalysis(false);
            require(command.applyTo(currentProgram, monitor), "Actual selected original disassembly at " + start + ": " + command.getStatusMsg());
            var instruction = currentProgram.getListing().getInstructionAt(start);
            require(instruction != null && instruction.getLength() == length, "Actual instruction boundary at " + start);
            var rows = currentProgram.getRelocationTable().getRelocations(application);
            require(rows.size() == 1, "One native relocation application at " + application + ": " + rows.size());
            var row = rows.get(0);
            require(row.getType() == selected[2] && (row.getValues()[1] & 0xff) == selected[3], "Source-qualified relocation type/flags at " + application);
            evidence.append("FILE ").append(Long.toHexString(selected[0])).append(" instruction ").append(start).append(' ').append(instruction)
                .append(" bytes=").append(HexFormat.of().formatHex(instruction.getBytes())).append(" application=").append(application)
                .append(" type=").append(row.getType()).append(" status=").append(row.getStatus()).append(" values=").append(Arrays.toString(row.getValues()))
                .append(" retained=").append(HexFormat.of().formatHex(row.getBytes())).append('\n');
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                var mask = instruction.getPrototype().getOperandValueMask(operand);
                evidence.append("  operand[").append(operand).append("] mask=").append(mask == null ? "null" : HexFormat.of().formatHex(mask.getBytes())).append('\n');
            }
        }
        Files.writeString(output.resolve("native-observations.txt"), evidence);
        if (args.length > 2 && args[2].equals("probe")) {
            println("NE PROVENANCE PROBE COMPLETE: " + cases.length + " actual native applications; " + output);
            return;
        }
        var analyzer = new NeRelocationProvenanceAnalyzer();
        var listing = currentProgram.getListing();
        Address preserved = mapped(cases[0][1]);
        String userNote = "User note: preserve this NE application, not a manufactured call edge.";
        String previous = listing.getComment(CommentType.EOL, preserved);
        require(previous != null && previous.contains(NeRelocationProvenanceAnalyzer.MARKER), "Installed analyzer must run automatically on native import before the validator reruns it");
        listing.setComment(preserved, CommentType.EOL, previous + "\n" + userNote);
        String references = referenceSnapshot();
        MessageLog log = new MessageLog();
        require(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analysis failed: " + log);
        require(references.equals(referenceSnapshot()), "Provenance annotation must not change any memory-sourced native reference");
        require(listing.getComment(CommentType.EOL, preserved).contains(userNote), "Existing user comment must survive");
        Map<Address, String> comments = commentSnapshot();
        Map<Integer, Integer> types = new TreeMap<>();
        Map<Integer, Integer> flags = new TreeMap<>();
        int applications = 0;
        var relocations = currentProgram.getRelocationTable().getRelocations();
        while (relocations.hasNext()) {
            var row = relocations.next();
            types.merge(row.getType(), 1, Integer::sum);
            flags.merge((int) row.getValues()[1] & 0xff, 1, Integer::sum);
            applications++;
        }
        require(comments.values().stream().mapToLong(value -> value.lines().filter(line -> line.startsWith(NeRelocationProvenanceAnalyzer.MARKER)).count()).sum() == applications, "One observation per native relocation row, including non-instruction applications");
        evidence.append("Whole native table annotations=").append(applications).append(" types=").append(types).append(" raw flags=").append(flags).append('\n');
        int callReferences = 0;
        for (long[] selected : cases) {
            Address start = mapped(selected[0]);
            Address application = mapped(selected[1]);
            var instruction = listing.getInstructionAt(start);
            var row = currentProgram.getRelocationTable().getRelocations(application).get(0);
            String comment = listing.getComment(CommentType.EOL, application);
            int owner = selected[2] == 5 ? 1 : 0;
            String expectedMask = selected[2] == 5 ? "00ffff" : "00ffffffff";
            require(expectedMask.equals(HexFormat.of().formatHex(instruction.getPrototype().getOperandValueMask(owner).getBytes())), "Actual selected operand mask changed at " + start);
            require(comment.contains("application=" + application) && comment.contains("operand[" + owner + "] fully covered by unique native mask"), "Exact application range must qualify the actual operand at " + application);
            require(comment.contains("runtime binding/whole edge unproved"), "Do not upgrade native load observations to runtime binding or whole-program edges");
            int nativeSegment = ((SegmentedAddress) application).getSegment();
            int sourceOffset = ((SegmentedAddress) application).getSegmentOffset();
            require((row.getValues()[0] & 0xffff) == nativeSegment, "Source tuple carries native segment ID, not NE ordinal");
            if (selected[2] == 3) {
                require(instruction.getFlowType().isCall(), "Actual native instruction is a call, independently of relocation");
                require(comment.contains("original-file=ffff0000 retained=ffff0000") && comment.contains("original-raw (chain storage, not loaded values) offset16=0xffff selector16=0x0000"), "Original unresolved offset/selector storage remains distinct from current loaded fields");
                require((row.getValues()[2] & 0xffff) == sourceOffset, "Selected FAR sites are independently documented singleton chains");
                for (var reference : instruction.getReferencesFrom()) {
                    if (reference.getReferenceType().isCall()) {
                        callReferences++;
                    }
                }
            }
            else {
                require((row.getValues()[2] & 0xffff) != sourceOffset, "Selected DLL applications must not be confused with their retained chain heads");
                require(comment.contains("no complete far target"), "A partial relocation must not fabricate a far target");
                if (selected[2] == 2) {
                    require(comment.contains("original-file=4518 retained=4518") && comment.contains("chain-head=0x0518") && comment.contains("offset not relocated"), "Selector-only chain and literal-offset boundary");
                }
                else {
                    require(!instruction.getFlowType().isCall(), "Immediate WORD relocation is not a CALL");
                    require(comment.contains("original-file=af13 retained=af13") && comment.contains("chain-head=0x2b0a") && comment.contains("selector not relocated"), "Immediate WORD chain and absent-selector boundary");
                }
            }
            evidence.append(comment).append('\n');
        }
        if (!corpus.equals("wavmix")) {
            require(callReferences >= cases.length, "Final original imports must retain existing native CALL references, not just decoded flow metadata");
        }
        if (corpus.equals("johnny")) {
            String comment = listing.getComment(CommentType.EOL, mapped(0xdd78));
            require(comment.contains("raw-target=internal NE-segment-ordinal=1 offset=0x0319"), "Johnny PCMP raw target remains qualified independently of callee semantics");
        }
        if (corpus.equals("simtower")) {
            require(listing.getComment(CommentType.EOL, mapped(0x231ce)).contains("raw-target=internal NE-segment-ordinal=51 offset=0x007e"), "Actual NE28 internal target provenance");
            require(listing.getComment(CommentType.EOL, mapped(0x231e4)).contains("raw-target=import module-index=5 ordinal=85"), "Actual NE28 imported ordinal remains a raw import, not a loaded binding");
        }
        require(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analysis rerun failed: " + log);
        require(comments.equals(commentSnapshot()), "Repeated analysis must leave all native application comments byte-for-byte unchanged");
        require(references.equals(referenceSnapshot()), "Repeated analysis must not duplicate native CALL or data references");
        evidence.append("Existing selected native CALL references=").append(callReferences).append("; unchanged memory-sourced references; stable all-application comments; preserved user note\n")
            .append("No unsupported-type semantic execution claim: only types present in the census were observed. No original binary was executed.\n");
        Files.writeString(output.resolve("qualified-provenance.txt"), evidence);
        println("NE PROVENANCE VALIDATION PASS: " + corpus + "; selected=" + cases.length + "; native applications=" + applications + "; unique operand masks, original/current parts, chain/application distinction, stable comments and unchanged references. Outputs: " + output);
    }

    private long[][] simtowerCases() {
        int[] sources = { 0x05ce, 0x05d6, 0x05e4, 0x0719, 0x05fa, 0x065d, 0x0779, 0x07af, 0x0615, 0x062d, 0x063c, 0x0682, 0x0731, 0x079c, 0x07d5, 0x0679, 0x0692, 0x0697, 0x0738, 0x074b, 0x075d, 0x07bd, 0x07cc };
        List<Integer> imports = List.of(0x05e4, 0x0719, 0x063c, 0x0682, 0x0731, 0x079c, 0x07d5, 0x0738, 0x074b, 0x075d);
        long[][] cases = new long[sources.length][];
        for (int i = 0; i < sources.length; i++) {
            cases[i] = new long[] { 0x22c00 + sources[i] - 1, 0x22c00 + sources[i], 3, imports.contains(sources[i]) ? 1 : 0 };
        }
        return cases;
    }

    private Address mapped(long fileOffset) {
        List<Address> mappings = currentProgram.getMemory().locateAddressesForFileOffset(fileOffset);
        require(mappings.size() == 1, "One native original file mapping for " + Long.toHexString(fileOffset) + ": " + mappings);
        return mappings.get(0);
    }

    private Map<Address, String> commentSnapshot() {
        Map<Address, String> comments = new LinkedHashMap<>();
        var rows = currentProgram.getRelocationTable().getRelocations();
        while (rows.hasNext()) {
            Address address = rows.next().getAddress();
            comments.put(address, currentProgram.getListing().getComment(CommentType.EOL, address));
        }
        return comments;
    }

    private String referenceSnapshot() {
        StringBuilder references = new StringBuilder();
        var manager = currentProgram.getReferenceManager();
        var sources = manager.getReferenceSourceIterator(currentProgram.getMemory(), true);
        while (sources.hasNext()) {
            for (var reference : manager.getReferencesFrom(sources.next())) {
                references.append(reference.getFromAddress()).append(' ').append(reference.getToAddress()).append(' ').append(reference.getOperandIndex())
                    .append(' ').append(reference.getReferenceType()).append(' ').append(reference.getSource()).append(' ').append(reference.isPrimary()).append('\n');
            }
        }
        return references.toString();
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
