// Native exact-image check. Arguments: qualified original BCC.EXE, private output directory, direct|automatic.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.Bcc20Profile;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateBcc20Profile extends GhidraScript {
    private ToolchainProfile.Context c;
    private byte[] original;
    private final StringBuilder result = new StringBuilder();
    // Independent source-note terminal-inclusive partitions: FILE start, exclusive end, argument cleanup, instruction count.
    private static final int[][] FUNCTIONS = {
        { 0x43d7a, 0x43db2, 6, 24 }, { 0x43db2, 0x43dfc, 6, 36 }, { 0x43dfc, 0x43e65, 6, 47 },
        { 0x43fc7, 0x43fe1, 6, 13 }, { 0x43d5b, 0x43d7a, 0, 16 },
        { 0x54350, 0x54386, 6, 22 }, { 0x543a6, 0x54435, 6, 57 }, { 0x66899, 0x66900, 8, 40 },
        { 0x6526e, 0x6529d, 2, 21 }, { 0x67e1a, 0x6802c, 0, 197 }, { 0x6824e, 0x682c1, 4, 51 },
        { 0x682c1, 0x682ec, 2, 19 }, { 0xba87, 0xbaa8, 8, 20 }, { 0xc072, 0xc09d, 8, 16 }, { 0xc146, 0xc180, 8, 22 },
        { 0x62dc6, 0x62f0b, 4, 116 }, { 0x62f80, 0x6317b, 4, 180 }, { 0x650a0, 0x651f0, 8, 111 },
        { 0x65930, 0x659a8, 20, 42 }, { 0x65db7, 0x65e44, 6, 48 }, { 0xbf23, 0xbf51, 8, 24 },
        { 0x1402, 0x1418, 8, 14 }, { 0x633c8, 0x6344c, 4, 51 }, { 0x78803, 0x788fa, 4, 95 }, { 0x631b0, 0x63200, 2, 27 },
        { 0x78f38, 0x79244, 2, 290 }, { 0x78de6, 0x78e86, 2, 71 }, { 0x78e86, 0x78f30, 4, 75 },
        { 0x792ca, 0x795a6, 4, 271 }, { 0x795da, 0x79622, 2, 29 }, { 0x6a642, 0x6a6a5, 2, 34 }, { 0x6a9bc, 0x6aa04, 4, 26 },
        { 0x6ea47, 0x6ee25, 0, 347 }, { 0x6fa2e, 0x6fa53, 6, 12 }, { 0x6f982, 0x6f99f, 4, 11 },
        { 0x6fb03, 0x6fda5, 2, 232 }, { 0x6fda5, 0x6fe45, 2, 59 }, { 0x6fe45, 0x700e1, 4, 220 },
        { 0x6405a, 0x64137, 6, 84 }, { 0x64137, 0x641a1, 2, 44 }, { 0x63251, 0x63265, 2, 11 },
        { 0x70107, 0x70168, 2, 33 }, { 0x70168, 0x7028f, 4, 100 }, { 0x64007, 0x64021, 2, 14 }
    };

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected original, private output, direct|automatic");
        boolean automatic = args[2].equals("automatic");
        Bcc20Profile profile = new Bcc20Profile();
        c = profile.match(currentProgram, monitor);
        require(c != null, "Expected exact original retained by native MZ import");
        original = Files.readAllBytes(Path.of(args[0]));
        checkOriginal();
        boolean activated = currentProgram.getSymbolTable().getSymbol("bcc20_obj_source_callbacks24", c.mapped(0x1435e), currentProgram.getGlobalNamespace()) != null;
        result.append("Ghidra ").append(getGhidraVersion()).append("; format ").append(currentProgram.getExecutableFormat()).append("; language ").append(currentProgram.getLanguageID()).append('\n');
        result.append("Profile marker present before script: ").append(activated).append("; requested mode: ").append(args[2]).append('\n');
        if (automatic) {
            require(activated, "Automatic activation required; direct application must not manufacture this result");
        }
        Map<Address, byte[]> nativeBytes = new LinkedHashMap<>();
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (block.isInitialized() && !block.getName().startsWith("bcc20_fbov_")) {
                byte[] bytes = new byte[(int) block.getSize()];
                require(currentProgram.getMemory().getBytes(block.getStart(), bytes) == bytes.length, "Incomplete native block snapshot");
                nativeBytes.put(block.getStart(), bytes);
            }
        }
        MessageLog log = new MessageLog();
        if (automatic) {
            result.append("Production automatic artifacts checked before any explicit reapplication.\n");
        }
        else {
            profile.prepareData(c, monitor, log);
            profile.applyFinalFacts(c, monitor, log);
            result.append("Canonical Bcc20Profile.prepareData/applyFinalFacts exercised directly; automatic activation is NOT tested in this mode.\n");
        }
        for (var entry : nativeBytes.entrySet()) {
            var block = currentProgram.getMemory().getBlock(entry.getKey());
            require(block != null && block.getStart().equals(entry.getKey()) && block.getSize() == entry.getValue().length, "Existing native block boundary changed");
            byte[] actual = new byte[entry.getValue().length];
            require(currentProgram.getMemory().getBytes(entry.getKey(), actual) == actual.length && Arrays.equals(actual, entry.getValue()), "Native resident/header bytes or relocations changed");
        }
        checkBodies();
        checkCallbacks(0x1435e);
        checkCallbacks(0x14442);
        reference(0x14386, 0xe3d7);
        reference(0x14386, 0x63596);
        reference(0xe3d9, 0x63596);
        reference(0x1446a, 0xedaa);
        reference(0x1446a, 0x78f38);
        reference(0x668a9, 0x543a6);
        reference(0x668b9, 0x543a6);
        reference(0x67e27, 0x6526e);
        reference(0x682b5, 0x66899);
        reference(0x67e43, 0xba87);
        reference(0x6827e, 0xc072);
        reference(0x6828c, 0xc146);
        reference(0x63166, 0x78803);
        reference(0x63173, 0x633c8);
        reference(0x62f03, 0x62f80);
        reference(0x65e3a, 0x67e1a);
        reference(0x631c6, 0x543a6);
        reference(0x70ba8, 0x6f982);
        reference(0x10768, 0x43dfc);
        bytes(0xe3d7, "cd3fe60300");
        bytes(0x1075e, "42009c0315170000");
        bytes(0x10766, "53009c0314170000");
        bytes(0x10796, "63009c03fc160000");
        bytes(0x43ddc, "ff5402");
        bytes(0x43e62, "c20600");
        bytes(0x13180, "5d50fe00c1030002020a0a0a00000029002d00");
        bytes(0x143be, "000402060307010506070504");
        require(word(0x13183) == 0xc100 && word(0x13184) == 0x03c1, "Tested unaligned+3 flag word must not be mistaken for overlapping+4");
        structure("OptionDescriptor8Partial", 8, new int[] { 0, 1, 2, 4 }, new int[] { 1, 1, 2, 2 });
        structure("RecordedOverlayDescriptor32Partial", 32, new int[] { 4, 6, 8, 10 }, new int[] { 2, 2, 2, 2 });
        structure("AppendDescriptor8Partial", 8, new int[] { 0, 2, 4, 6 }, new int[] { 2, 2, 2, 2 });
        structure("PrimaryNode4Partial", 4, new int[] { 0, 1, 2 }, new int[] { 1, 1, 1 });
        structure("SecondaryNode4Partial", 4, new int[] { 0, 2 }, new int[] { 2, 2 });
        structure("InstructionDescriptor19Partial", 19, new int[] { 0, 2, 3, 7, 13, 15, 17 }, new int[] { 2, 1, 2, 1, 2, 2, 2 });
        for (int[] function : FUNCTIONS) {
            function(function);
        }
        checkOperandAndZeroCandidates();
        instruction(0xbaa0, "98", false);
        instruction(0xbf4e, "ca0800", true);
        instruction(0x140f, "f3a4", true);
        for (int[] table : new int[][] { { 0x43e65, 0x43e75 }, { 0x79264, 0x79270 }, { 0x795a6, 0x795da }, { 0x7105b, 0x7105d }, { 0x63eab, 0x63ead }, { 0x63f11, 0x63f13 }, { 0x63ef9, 0x63efb } }) {
            var data = currentProgram.getListing().getDefinedDataAt(c.mapped(table[0]));
            require(data != null && data.getLength() == table[1] - table[0], "Selected raw table must be defined data");
            require(!currentProgram.getListing().getInstructions(c.range(table[0], table[1]), true).hasNext(), "Table must not be fabricated instructions");
        }
        require(currentProgram.getFunctionManager().getFunctionAt(c.mapped(0x63596)) == null, "Partial object callback prefix must not become a complete profile function");
        require(currentProgram.getListing().getComment(CommentType.PLATE, c.mapped(0x63596)).contains("NOT a complete function"), "Partial callback qualification missing");
        // Original relative CALL in actual overlay; verifies native overlay flow, not a synthetic opcode sample.
        var near = currentProgram.getListing().getInstructionAt(c.mapped(0x6fa4c));
        require(near != null && near.getFlowType().isCall() && Arrays.asList(near.getFlows()).contains(c.mapped(0x6fb03)), "Original near018c CALL must remain in0508 analysis overlay");

        int blockCount = currentProgram.getMemory().getBlocks().length;
        int typeCount = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbolCount = currentProgram.getSymbolTable().getNumSymbols();
        int referenceCount = currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x543a6));
        int selectorReferenceCount = currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x64007));
        int sharedReferenceCount = currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x63cb2));
        String sharedBefore = currentProgram.getListing().getComment(CommentType.PLATE, c.mapped(0x63cb2));
        String before = currentProgram.getListing().getComment(CommentType.PLATE, c.mapped(0x63596));
        reapply(profile, log, automatic);
        require(blockCount == currentProgram.getMemory().getBlocks().length && typeCount == currentProgram.getDataTypeManager().getDataTypeCount(true) && symbolCount == currentProgram.getSymbolTable().getNumSymbols(), "Actual repeated application duplicated blocks/types/labels");
        require(referenceCount == currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x543a6)) && before.equals(currentProgram.getListing().getComment(CommentType.PLATE, c.mapped(0x63596))), "Actual repeated application duplicated selected references/comments");
        require(selectorReferenceCount == currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x64007)) && sharedReferenceCount == currentProgram.getReferenceManager().getReferenceCountTo(c.mapped(0x63cb2)) && sharedBefore.equals(currentProgram.getListing().getComment(CommentType.PLATE, c.mapped(0x63cb2))), "Repeated application changed candidate references/comments");
        var guarded = currentProgram.getFunctionManager().getFunctionAt(c.mapped(0x543a6));
        guarded.setName("user_owned_bcc20_append", SourceType.USER_DEFINED);
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        String signature = guarded.getPrototypeString(true, true);
        AddressSet guardedBody = new AddressSet(guarded.getBody());
        c.program().getListing().setComment(c.mapped(0x63596), CommentType.PLATE, "User annotation\n" + before);
        reapply(profile, log, automatic);
        require(signature.equals(guarded.getPrototypeString(true, true)) && guardedBody.equals(guarded.getBody()) && guarded.getSignatureSource() == SourceType.USER_DEFINED, "Higher-priority user function/signature changed");
        require(c.program().getListing().getComment(CommentType.PLATE, c.mapped(0x63596)).equals("User annotation\n" + before), "User comment not preserved or duplicated");
        checkOriginal();
        result.append("Native resident/header bytes including all existing MZ relocation results unchanged; original FileBytes literally equal named input.\n");
        result.append("Repeated application: actual blocks/types/labels/selected references/comments stable. Actual user function/signature and plate comment preserved.\n");
        result.append("No original execution, overlay runtime relocation/selector claim, simultaneous residency or generic FBOV support.\n").append(log);
        Files.writeString(Path.of(args[1]).resolve("bcc20-profile-validation.txt"), result);
        println("BCC20 PROFILE VALIDATION PASS (" + args[2] + "; automatic activation tested=" + automatic + "): original equality, native resident relocation preservation, recorded overlay bytes/joins, selected complete functions/data, repeated application and user-source preservation.");
    }

    private void checkOperandAndZeroCandidates() throws Exception {
        for (int[] call : new int[][] {
            { 0x70063, 0x70168 }, { 0x7008d, 0x70107 }, { 0x7017b, 0x70107 },
            { 0x70279, 0x70168 }, { 0x70285, 0x70168 }
        }) {
            var instruction = currentProgram.getListing().getInstructionAt(c.mapped(call[0]));
            require(instruction != null && instruction.getLength() == 3 && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(c.mapped(call[1])), "Missing actual operand/selector native near CALL at FILE" + Integer.toHexString(call[0]));
            require(Byte.toUnsignedInt(original[call[0]]) == 0xe8 && call[0] + 3 + (short) word(call[0] + 1) == call[1], "Original signed near-call operand disagrees");
        }
        // Exact native instructions protect partial AL/AH effects, frame reloads and the fresh second-child order, not a guessed source expression.
        instruction(0x70271, "57", false);
        instruction(0x70272, "8e069886", false);
        instruction(0x70276, "26ff34", false);
        instruction(0x7027c, "57", false);
        instruction(0x7027d, "8e069886", false);
        instruction(0x70281, "26ff7402", false);
        instruction(0x70091, "8b5efe", false);
        instruction(0x70098, "268a4702", false);
        instruction(0x7009c, "50", false);
        instruction(0x701e0, "268a04", false);
        instruction(0x701e3, "b400", false);
        instruction(0x64014, "8a4402", false);
        instruction(0x64019, "b0ff", false);
        instruction(0x6fc89, "833e288b01", false);
        instruction(0x6fc90, "833e318b04", false);
        instruction(0x6fc97, "833e368b00", false);
        instruction(0x6fc9e, "be4f00", false);
        instruction(0x6fca1, "c706318b0100", false);
        instruction(0x6fca7, "a02c8b", false);
        instruction(0x6fcaa, "a2358b", false);
        for (int file : new int[] { 0x139d0, 0x139e3, 0x13a1c, 0x13465 }) {
            var row = currentProgram.getListing().getDefinedDataAt(c.mapped(file));
            require(row != null && row.getLength() == 19 && row.getDataType().getName().equals("InstructionDescriptor19Partial"), "Missing actual mnemonic descriptor");
            int literal = file == 0x13465 ? 0x13f8d : 0x1405c;
            require(0xeef0 + word(file) == literal, "Descriptor mnemonic offset differs");
            reference(file, literal);
        }
        bytes(0x13465, "9d50fe1041030002020a0a0a00000031003500");
        bytes(0x13f8d, "786f7200");
        bytes(0x1405c, "6d6f7600");
        require(word(0x63ef9) == 0x0b02 && word(0x63eab) == 0x0b02, "SUB and XOR must share their actual dispatch arm, not descriptors");
        reference(0x63ef9, 0x63cb2);
        reference(0x63eab, 0x63cb2);
        require(currentProgram.getFunctionManager().getFunctionAt(c.mapped(0x63cb2)) == null, "Partial shared SUB/XOR arm must not become a complete profile function");
        // Decode actual current native memory without creating instructions or claiming complete partial functions.
        for (int[] part : new int[][] { { 0x63cb2, 0x63cee, 27 }, { 0x641a1, 0x641be, 14 }, { 0x64268, 0x64274, 8 } }) {
            partialInstructions(part[0], part[1], part[2]);
        }
        for (int[] call : new int[][] {
            { 0x635b1, 0x64007 }, { 0x635c1, 0x64007 }, { 0x63cb5, 0x6405a },
            { 0x63cd3, 0x631b0 }, { 0x63cde, 0x63251 }, { 0x63ce8, 0x641a1 },
            { 0x641b3, 0x63251 }, { 0x6426a, 0x631b0 }
        }) {
            var decoded = new PseudoDisassembler(currentProgram).disassemble(c.mapped(call[0]));
            require(decoded != null && decoded.getLength() == 3 && decoded.getFlowType().isCall() && Arrays.asList(decoded.getFlows()).contains(c.mapped(call[1])), "Actual partial-code native near operand differs at FILE" + Integer.toHexString(call[0]));
            reference(call[0] + 1, call[1]);
        }
        bytes(0x63cb8, "0bc07403"); // Test returned shortening AX, not an assumed entry state.
        bytes(0x63cbf, "8b440f8946fc833e288b0175228a46fc0402500e");
        bytes(0x63cd6, "b8318b50a02c8b50"); // Fresh first selector after the opcode append.
        bytes(0x641aa, "833c01750f8a440450"); // Fresh second kind/selector, not a cached equal selector.
        bytes(0x641b6, "02460404c0");
        require(Byte.toUnsignedInt(original[0x143be]) == 0 && Byte.toUnsignedInt(original[0x143c0]) == 2, "Actual selected signed-byte mapping entries differ");
        int opcode = (word(0x13465 + 15) + 2) & 0xff;
        int pair00 = (0xc0 + Byte.toUnsignedInt(original[0x143be]) * 9) & 0xff;
        int pair02 = (0xc0 + Byte.toUnsignedInt(original[0x143c0]) * 9) & 0xff;
        require(opcode == 0x33 && pair00 == 0xc0 && pair02 == 0xd2, "Conditional actual-descriptor/map byte requests differ");
        result.append("R357/R363 and R335: three complete new functions and five actual native near joins checked; numeric selector/AL-AH/fresh frame and second-child boundaries retained.\n");
        result.append("R335: actual MOV/XOR descriptor/literal and shared SUB/XOR dispatch joins, current zero-arm instructions, native partial-call operands and conditional33c0/33d2 request arithmetic checked. No upstream wide-request producer or completed physical output proved.\n");
    }

    private void partialInstructions(int start, int end, int expectedCount) throws Exception {
        PseudoDisassembler decoder = new PseudoDisassembler(currentProgram);
        int cursor = start;
        int count = 0;
        while (cursor < end) {
            var instruction = decoder.disassemble(c.mapped(cursor));
            require(instruction != null && cursor + instruction.getLength() <= end && Arrays.equals(instruction.getBytes(), Arrays.copyOfRange(original, cursor, cursor + instruction.getLength())), "Partial native decoding differs at FILE" + Integer.toHexString(cursor));
            cursor += instruction.getLength();
            count++;
        }
        require(cursor == end && count == expectedCount, "Partial native instruction extent/count differs");
        result.append("PARTIAL FILE[").append(Integer.toHexString(start)).append(',').append(Integer.toHexString(end)).append(") native decoded instructions=").append(count).append("; not a complete function\n");
    }

    private void analyzeProfileChanges(String profileId) throws Exception {
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        int logStart = manager.getMessageLog().toString().length();
        StringBuilder finalLog = new StringBuilder();
        // The manager clears its log after notifying completion listeners.
        AutoAnalysisManagerListener listener = (completedManager, cancelled) -> {
            String messages = completedManager.getMessageLog().toString();
            if (!cancelled && messages.length() > logStart) {
                finalLog.append(messages.substring(logStart));
            }
        };
        manager.addListener(listener);
        try {
            analyzeChanges(currentProgram);
        }
        finally {
            manager.removeListener(listener);
        }
        require(finalLog.toString().contains("Applied " + profileId + " final facts"), "Production final stage must execute successfully before rerun assertions: " + finalLog);
    }

    private void reapply(Bcc20Profile profile, MessageLog log, boolean automatic) throws Exception {
        if (automatic) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production repeated analysis failed: " + log);
            analyzeProfileChanges(profile.id());
        }
        else {
            profile.prepareData(c, monitor, log);
            profile.applyFinalFacts(c, monitor, log);
        }
    }

    private void checkOriginal() throws Exception {
        byte[] imported = new byte[(int) c.original().getSize()];
        require(c.original().getOriginalBytes(0, imported) == imported.length && Arrays.equals(imported, original), "Imported original must be literally byte-equal to named source input");
    }

    private int word(int file) {
        return Byte.toUnsignedInt(original[file]) | Byte.toUnsignedInt(original[file + 1]) << 8;
    }

    private void bytes(int file, String hex) throws Exception {
        byte[] expected = java.util.HexFormat.of().parseHex(hex);
        require(Arrays.equals(Arrays.copyOfRange(original, file, file + expected.length), expected), "Contradictory qualified original FILE " + Integer.toHexString(file));
    }

    private void checkBodies() throws Exception {
        for (int[] body : new int[][] {
            { 0x0338, 0x43a60, 0x10c7, 0x9a }, { 0x0378, 0x4b6b0, 0x522, 0x48 }, { 0x03e0, 0x54350, 0x151, 8 },
            { 0x0458, 0x62db0, 0x19c, 0x2a }, { 0x0460, 0x62f80, 0x1fb, 0x24 }, { 0x0470, 0x631b0, 0x10c4, 0x44 },
            { 0x0488, 0x650a0, 0x753, 0x28 }, { 0x0490, 0x65830, 0xf2e, 0x3c }, { 0x0498, 0x667c0, 0x2b1, 0x12 },
            { 0x04a0, 0x66a90, 0x2251, 0x184 }, { 0x04c8, 0x69d70, 0xceb, 0x8a }, { 0x04f8, 0x6e460, 0x11b5, 0x110 },
            { 0x0508, 0x6f8c0, 0x9f3, 0x10 }, { 0x0510, 0x702d0, 0x1209, 0xaa }, { 0x0598, 0x78700, 0x1057, 0x14a }
        }) {
            var block = currentProgram.getMemory().getBlock(String.format("bcc20_fbov_%04x_analysis", body[0]));
            require(block != null && block.isOverlay() && block.getSize() == body[2] + body[3] && block.getStart().getOffset() == 0, "Incorrect recorded analysis block");
            byte[] actual = new byte[(int) block.getSize()];
            require(currentProgram.getMemory().getBytes(block.getStart(), actual) == actual.length && Arrays.equals(actual, Arrays.copyOfRange(original, body[1], body[1] + actual.length)), "Mapped real overlay bytes differ from original");
            require(c.mapped(body[1]).equals(block.getStart()) && c.mapped(body[1] + actual.length - 1).equals(block.getEnd()), "Ambiguous native FileBytes mapping");
            int descriptor = 0x1000 + 16 * word(0xc390 + body[0]);
            reference(0xc390 + body[0], descriptor);
            reference(descriptor + 4, body[1]);
            for (int field : new int[] { 4, 6, 8, 10 }) {
                var data = currentProgram.getListing().getDefinedDataAt(c.mapped(descriptor + field));
                require(data != null && data.getLength() == 2, "Recorded descriptor fields must remain native WORD data without merging loader blocks");
            }
            var fixups = currentProgram.getListing().getDefinedDataAt(c.mapped(body[1] + body[2]));
            require(fixups != null && fixups.getLength() == body[3], "Raw fixup offsets must be native data, not instructions");
            require(!currentProgram.getListing().getInstructions(c.range(body[1] + body[2], body[1] + body[2] + body[3]), true).hasNext(), "Fixup list was fabricated code");
            result.append("OVERLAY row").append(Integer.toHexString(body[0])).append(" FILE").append(Integer.toHexString(body[1])).append(" native ").append(block.getStart()).append(" bytes=").append(actual.length).append(" literally equal original; raw fixups retained\n");
        }
    }

    private void checkCallbacks(int file) throws Exception {
        var data = currentProgram.getListing().getDefinedDataAt(c.mapped(file));
        require(data != null && data.getDataType() instanceof Array && ((Array) data.getDataType()).getNumElements() == 24 && data.getLength() == 96, "Expected24 FAR cells/96bytes");
        for (int i = 0; i < 24; i++) {
            int source = file + 4 * i;
            int target = 0x1000 + word(source + 2) * 16 + word(source);
            reference(source, target);
            Address segment = c.mapped(source + 2);
            require(currentProgram.getRelocationTable().getRelocations(segment).stream().anyMatch(r -> r.getStatus() == Relocation.Status.APPLIED && r.getType() == 0), "Missing native MZ source-cell relocation");
            var pointer = currentProgram.getMemory();
            int loadedOffset = Short.toUnsignedInt(pointer.getShort(c.mapped(source)));
            int loadedSegment = Short.toUnsignedInt(pointer.getShort(segment));
            Address loaded = ((ghidra.program.model.address.SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace()).getAddress(loadedSegment, loadedOffset);
            require(loaded.equals(c.mapped(target)), "Real relocated table cell must point to recorded resident stub");
        }
        result.append("TABLE FILE").append(Integer.toHexString(file)).append(": all24 native MZ cell relocations and static resident targets checked\n");
    }

    private void function(int[] specification) {
        int start = specification[0];
        int end = specification[1];
        var function = currentProgram.getFunctionManager().getFunctionAt(c.mapped(start));
        require(function != null && function.getBody().equals(c.range(start, end)) && function.getStackPurgeSize() == specification[2], "Incorrect complete function extent/cleanup at FILE" + Integer.toHexString(start));
        Address cursor = c.mapped(start);
        int count = 0;
        while (cursor.compareTo(c.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(c.mapped(end - 1)) <= 0, "Incomplete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            count++;
        }
        require(count == specification[3], "Native instruction count differs at FILE" + Integer.toHexString(start) + ": " + count);
        int terminal = specification[2] == 0 ? end - 1 : end - 3;
        int opcode = Byte.toUnsignedInt(original[terminal]);
        require((opcode == 0xc2 || opcode == 0xca || opcode == 0xc3 || opcode == 0xcb) && (specification[2] == 0 || word(terminal + 1) == specification[2]), "Full original terminal/cleanup must agree with contract");
        result.append("FUNCTION FILE[").append(Integer.toHexString(start)).append(',').append(Integer.toHexString(end)).append(") purge=").append(specification[2]).append(" native instructions=").append(count).append('\n');
    }

    private void instruction(int file, String hex, boolean crossesBlock) throws Exception {
        byte[] expected = java.util.HexFormat.of().parseHex(hex);
        var instruction = currentProgram.getListing().getInstructionAt(c.mapped(file));
        require(instruction != null && instruction.getLength() == expected.length && Arrays.equals(instruction.getBytes(), expected) && instruction.getMaxAddress().equals(c.mapped(file + expected.length - 1)), "Native instruction must retain full original bytes/boundary at FILE" + Integer.toHexString(file));
        require(crossesBlock == !currentProgram.getMemory().getBlock(instruction.getMinAddress()).equals(currentProgram.getMemory().getBlock(instruction.getMaxAddress())), "Native instruction block relationship changed");
        result.append("INSTRUCTION FILE").append(Integer.toHexString(file)).append(" native ").append(instruction.getMinAddress()).append("..").append(instruction.getMaxAddress()).append(" bytes=").append(hex).append(" crosses original native blocks=").append(crossesBlock).append('\n');
    }

    private void reference(long source, long destination) {
        var reference = currentProgram.getReferenceManager().getReference(c.mapped(source), c.mapped(destination), 0);
        require(reference != null && reference.getReferenceType() == RefType.DATA, "Missing qualified static DATA relationship FILE" + Long.toHexString(source) + "->" + Long.toHexString(destination));
    }

    private void structure(String name, int length, int[] offsets, int[] sizes) {
        var type = currentProgram.getDataTypeManager().getDataType(Bcc20Profile.TYPES, name);
        require(type instanceof Structure && type.getLength() == length, "Missing partial structure " + name);
        for (int i = 0; i < offsets.length; i++) {
            var component = ((Structure) type).getComponentAt(offsets[i]);
            require(component != null && component.getOffset() == offsets[i] && component.getLength() == sizes[i], "Incorrect field in " + name);
        }
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
