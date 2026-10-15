// Native exact-image integration check. Arguments: source-qualified original BCC.EXE, existing private output directory.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.Bcc45Profile;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateBcc45Profile extends GhidraScript {
    private ToolchainProfile.Context context;
    private final StringBuilder result = new StringBuilder();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 2, "Expected original path and private output directory");
        Path output = Path.of(args[1]);
        context = new Bcc45Profile().match(currentProgram, monitor);
        require(context != null, "Native NE import must retain the exact qualified original FileBytes");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Imported original must be literally byte-equal to the named input, not relocated-memory equality");
        require(currentProgram.getSymbolTable().getSymbol("bcc45_asm_source_callbacks26", context.mapped(0x16fb2), currentProgram.getGlobalNamespace()) != null, "Production analyzer must have applied the profile during initial native analysis");
        result.append("Ghidra ").append(getGhidraVersion()).append("; format ").append(currentProgram.getExecutableFormat()).append("; language ").append(currentProgram.getLanguageID()).append('\n');
        result.append("Original FileBytes literally equal named source input: ").append(original.length).append(" bytes\n");

        checkCallbacks(0x16fb2);
        checkCallbacks(0x1751c);
        checkReference(0x16fda, 62, 0xc45, 0xa7845);
        checkReference(0x17544, 63, 0x7dd, 0xa95dd);
        checkReference(0x16ff2, 62, 0xca, 0xa6cca);
        checkReference(0x1755c, 63, 0x2e7, 0xa90e7);
        checkReference(0xa6cd9, 56, 0x207, 0x98607);
        checkReference(0xa90f6, 56, 0x207, 0x98607);
        for (long call : new long[] { 0xa6cd8, 0xa90f5 }) {
            var instruction = currentProgram.getListing().getInstructionAt(context.mapped(call));
            require(instruction != null && instruction.getFlowType().isCall() && Arrays.asList(instruction.getFlows()).contains(context.mapped(0x98607)), "Real branch-wrapper CALL must resolve through native relocation to NE56:0207");
        }
        checkFunction(0xa700b, 0xa7121, 4, 99);
        checkFunction(0xa9412, 0xa9493, 4, 50);
        checkFunction(0xa7845, 0xa7c50, 2, 329);
        checkFunction(0xa95dd, 0xa9f3c, 2, 841);
        checkFunction(0xa7e8b, 0xa7ea9, 2, 15);
        checkFunction(0xa7ea9, 0xa82e1, 4, 343);
        checkFunction(0xa6cca, 0xa6ce3, 6, 12);
        checkFunction(0xa90e7, 0xa9100, 6, 12);
        checkDataWords(0xa7c50, 0xa7cc2);
        checkDataWords(0xa9f3c, 0xaa146);
        checkDataWords(0xa82e1, 0xa8327);
        checkDataWords(0xa24d0, 0xa24d8);

        checkStructure("SectionPiece28Partial", 28, new int[] { 2, 4, 10, 12, 14, 18, 26 }, new int[] { 2, 2, 2, 2, 2, 2, 2 });
        checkStructure("ControlNode16Partial", 16, new int[] { 2, 4, 6, 8, 14 }, new int[] { 2, 2, 2, 2, 2 });
        checkStructure("FixupQueueRecord8", 8, new int[] { 0, 2, 6 }, new int[] { 2, 4, 2 });
        checkFunction(0x98441, 0x9849d, 0, 26);
        checkFunction(0x9849d, 0x984df, 0, 21);
        checkFunction(0x98532, 0x9858c, 6, 31);
        checkFunction(0x98607, 0x986cd, 6, 64);
        checkFunction(0x894a3, 0x89521, 0, 43);
        checkFunction(0xae33a, 0xae436, 8, 85);
        require(currentProgram.getFunctionManager().getFunctionAt(context.mapped(0xae436)) == null || !currentProgram.getFunctionManager().getFunctionAt(context.mapped(0xae436)).getName().equals("bcc45_construct_parallel_backend_record"), "1036 is not the0f3a constructor entry");

        checkStructure("PseudoregisterRow7", 7, new int[] { 0, 2, 4 }, new int[] { 2, 2, 1 });
        checkStructure("SymbolPartial", 0x23, new int[] { 14, 22, 34 }, new int[] { 4, 2, 1 });
        checkStructure("SymbolReferenceNodePartial", 0x12, new int[] { 0, 2, 4, 8, 12, 16 }, new int[] { 2, 2, 2, 4, 4, 2 });
        checkOriginalBytes(0x165c6, "224100000a0a00");
        checkOriginalBytes(0x165cd, "274102000a0d00");
        checkOriginalBytes(0x1660c, "52410000080000");
        checkOriginalBytes(0x16722, "5f45415800");
        checkOriginalBytes(0x16727, "5f45445800");
        checkFunction(0x67360, 0x67389, 4, 17);
        checkFunction(0x5cefb, 0x5cf65, 14, 39);
        checkFunction(0x88a4d, 0x88ae1, 4, 55);
        for (String domain : new String[] { "NodeTag", "NodeCategory", "BackendRecordTag", "InstructionRequestTag" }) {
            require(currentProgram.getDataTypeManager().getDataType(Bcc45Profile.TYPES, domain) != null, "Missing distinct numeric domain " + domain);
        }
        require(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x6ea71)).contains("not a complete function"), "Registration-loop fragment must not claim a complete containing function");

        checkOriginalBytes(0x140c6, "6b02360697190000");
        checkOriginalBytes(0x17584, "000402060307010506070504");
        checkOriginalBytes(0x14306, "ff02b5089a190000");
        checkOriginalBytes(0x142a6, "0002b5080f1a0400");
        checkOriginalBytes(0x143ce, "0001b5089a190100");
        checkStructure("ByteStoreOptionRow8", 8, new int[] { 0, 1, 2, 4, 6 }, new int[] { 1, 1, 2, 2, 1 });
        checkFunction(0x6d6b5, 0x6d6cc, 6, 11);
        checkFunction(0x6d436, 0x6d4a9, 6, 48);
        checkFunction(0x94200, 0x9423d, 0, 22);
        checkFunction(0x895f1, 0x8968e, 26, 48);
        checkFunction(0x9430e, 0x94491, 0, 127);
        checkFunction(0xad705, 0xadb49, 2, 311);
        // Original qualified normalizer instructions, not a synthetic workspace scenario.
        checkOriginalBytes(0xad8db, "834604c2");
        checkOriginalBytes(0xad8df, "c70659a60100");
        require(currentProgram.getListing().getInstructionAt(context.mapped(0xad8db)) != null, "Native instruction must own the actual009c->005e operation");

        int typeCount = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        String before = currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x895f1));
        ToolchainProfileAnalyzer analyzer = new ToolchainProfileAnalyzer();
        MessageLog log = new MessageLog();
        require(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log), "Production repeated analysis failed: " + log);
        require(typeCount == currentProgram.getDataTypeManager().getDataTypeCount(true), "Repeated analysis must not duplicate types");
        require(symbols == currentProgram.getSymbolTable().getNumSymbols(), "Repeated analysis must not duplicate labels");
        require(before.equals(currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(0x895f1))), "Repeated analysis must not duplicate profile comments");
        result.append("Production repeated-analysis assertions passed: no duplicate datatypes, labels or selected comments.\n");

        // Disposable validation Program: exercise the real source-priority policy on an actual profile function.
        Function guarded = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x98607));
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        guarded.setName("user_owned_branch_signature", SourceType.USER_DEFINED);
        String signature = guarded.getPrototypeString(true, true);
        AddressSet guardedBody = new AddressSet(guarded.getBody());
        require(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log), "Production user-priority rerun failed: " + log);
        require(signature.equals(guarded.getPrototypeString(true, true)) && guardedBody.equals(guarded.getBody()) && guarded.getSignatureSource() == SourceType.USER_DEFINED, "Analyzer must preserve the user-owned actual function/signature");
        result.append("Production user-source preservation passed on actual branch constructor; disposable validation Program intentionally retains this user-owned signature.\n");
        result.append(log).append('\n');
        Files.writeString(output.resolve("bcc45-profile-validation.txt"), result);
        println("BCC45 PROFILE VALIDATION PASS: exact original bytes, native mapping/relocations, all52 callback references, separate layouts, complete selected extents, state/normalizer, repeated analysis and user-source preservation. " + output);
    }

    private void checkCallbacks(long fileOffset) throws Exception {
        var data = currentProgram.getListing().getDefinedDataAt(context.mapped(fileOffset));
        require(data != null && data.getDataType() instanceof Array && ((Array) data.getDataType()).getNumElements() == 26 && data.getLength() == 104, "Expected26 four-byte FAR storage records at original FILE " + Long.toHexString(fileOffset));
        for (int i = 0; i < 26; i++) {
            Address cell = context.mapped(fileOffset + i * 4L);
            var relocations = currentProgram.getRelocationTable().getRelocations(cell);
            require(relocations.size() == 1 && relocations.get(0).getStatus() == Relocation.Status.APPLIED && relocations.get(0).getType() == 3, "Expected singleton applied native FAR relocation at " + cell);
            long[] values = relocations.get(0).getValues();
            require(values.length == 5 && values[1] == 0, "Expected internal nonadditive native metadata at " + cell);
            int offset = Short.toUnsignedInt(currentProgram.getMemory().getShort(cell));
            int selector = Short.toUnsignedInt(currentProgram.getMemory().getShort(cell.add(2)));
            Address target = ((ghidra.program.model.address.SegmentedAddressSpace) cell.getAddressSpace()).getAddress(selector, offset);
            require(offset == (values[4] & 0xffff), "Loaded FAR offset must match the native NE target offset");
            var reference = currentProgram.getReferenceManager().getReference(cell, target, 0);
            require(reference != null && reference.getReferenceType() == RefType.DATA, "Table relocation must become a DATA reference, not an invented unconditional CALL");
            result.append("TABLE FILE ").append(Long.toHexString(fileOffset + i * 4L)).append(" native ").append(cell).append(" -> NE").append(values[3]).append(':').append(Long.toHexString(values[4] & 0xffff)).append(" native ").append(target).append(" DATA\n");
        }
    }

    private void checkReference(long source, int ordinal, int offset, long destination) {
        Address cell = context.mapped(source);
        Address target = context.mapped(destination);
        require(currentProgram.getReferenceManager().getReference(cell, target, 0) != null, "Missing qualified source/target reference at " + cell);
        require(currentProgram.getRelocationTable().getRelocations(cell).stream().anyMatch(r -> r.getType() == 3 && r.getValues().length == 5 && (r.getValues()[3] & 0xffff) == ordinal && (r.getValues()[4] & 0xffff) == offset), "Missing owner-qualified native NE target relationship");
    }

    private void checkFunction(long start, long end, int purge, int count) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(start));
        require(function != null && function.getBody().equals(context.range(start, end)), "Incorrect complete function extent at FILE " + Long.toHexString(start));
        require(function.getStackPurgeSize() == purge, "Incorrect argument cleanup at " + function.getEntryPoint());
        Address cursor = context.mapped(start);
        int actual = 0;
        while (cursor.compareTo(context.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(context.mapped(end - 1)) <= 0, "Incomplete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            actual++;
        }
        require(actual == count, "Native instruction count disagrees with qualified original body at " + function.getEntryPoint() + ": " + actual + " versus " + count);
        result.append("FUNCTION FILE [").append(Long.toHexString(start)).append(',').append(Long.toHexString(end)).append(") ").append(function.getEntryPoint()).append(" purge=").append(purge).append(" native-instructions=").append(actual).append('\n');
    }

    private void checkDataWords(long start, long end) {
        var data = currentProgram.getListing().getDefinedDataAt(context.mapped(start));
        require(data != null && data.getLength() == end - start && data.getDataType() instanceof Array, "Adjacent switch table must be native data");
        for (var instruction : currentProgram.getListing().getInstructions(context.range(start, end), true)) {
            throw new IllegalStateException("Adjacent switch-table bytes misidentified as instruction " + instruction);
        }
    }

    private void checkStructure(String name, int length, int[] offsets, int[] sizes) {
        var type = currentProgram.getDataTypeManager().getDataType(Bcc45Profile.TYPES, name);
        require(type instanceof Structure && type.getLength() == length, "Missing native partial structure " + name);
        Structure structure = (Structure) type;
        for (int i = 0; i < offsets.length; i++) {
            var field = structure.getComponentAt(offsets[i]);
            require(field != null && field.getOffset() == offsets[i] && field.getLength() == sizes[i], "Incorrect qualified field in " + name + " at " + offsets[i]);
        }
        result.append("TYPE ").append(type.getPathName()).append(" length=").append(length).append(" qualified-fields=").append(offsets.length).append('\n');
    }

    private void checkOriginalBytes(long offset, String hex) throws Exception {
        byte[] expected = java.util.HexFormat.of().parseHex(hex);
        byte[] actual = new byte[expected.length];
        require(context.original().getOriginalBytes(offset, actual) == actual.length && Arrays.equals(expected, actual), "Contradictory qualified original bytes at FILE " + Long.toHexString(offset));
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
