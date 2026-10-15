// Native exact-image assertions. Arguments: original BCC3.1 path, private output directory, direct|automatic.
//@category LegacyToolchains

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import dev.sangoi.ghidra.legacy.ToolchainProfileAnalyzer;
import dev.sangoi.ghidra.legacy.profiles.Bcc31Profile;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ValidateBcc31Profile extends GhidraScript {
    private ToolchainProfile.Context context;
    private final StringBuilder result = new StringBuilder();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 && (args[2].equals("direct") || args[2].equals("automatic")), "Expected original path, private output directory and direct|automatic (no silent fallback)");
        Bcc31Profile profile = new Bcc31Profile();
        context = profile.match(currentProgram, monitor);
        require(context != null, "Native NE import must retain the exact qualified original FileBytes");
        byte[] expected = Files.readAllBytes(Path.of(args[0]));
        byte[] original = new byte[(int) context.original().getSize()];
        require(context.original().getOriginalBytes(0, original) == original.length && Arrays.equals(expected, original), "Imported original must literally equal the named source input, not relocated memory");
        MessageLog log = new MessageLog();
        if (args[2].equals("direct")) {
            profile.apply(context, monitor, log);
            result.append("EXPLICIT DIRECT PROFILE APPLICATION; automatic registry activation not asserted.\n");
        }
        else {
            require(hasLabel(0x19574, "bcc31_object_source_callbacks26"), "Automatic mode requires production analyzer activation before this script; no apply fallback");
            result.append("AUTOMATIC PRODUCTION ANALYZER ACTIVATION asserted before script application.\n");
        }
        result.append("Ghidra ").append(getGhidraVersion()).append("; ").append(currentProgram.getExecutableFormat()).append("; ").append(currentProgram.getLanguageID()).append("; original byte equality ").append(original.length).append('\n');

        // External expectations are actual R174/R294 original descriptors and instruction bodies.
        originalBytes(0x1581d, "4200eb05981a0000");
        originalBytes(0x15825, "5300eb05971a0000");
        originalBytes(0x15855, "6300eb05731a0000");
        originalBytes(0x1589d, "5000130f00000000");
        var option = currentProgram.getListing().getDefinedDataAt(context.mapped(0x15825));
        require(option != null && option.getLength() == 8 && ((ghidra.program.model.scalar.Scalar) option.getComponentContaining(2).getValue()).getUnsignedValue() == 0x5eb, "S descriptor must expose near handler WORD, not four-byte FAR storage");
        reference(0x15827, 0x55deb, RefType.DATA);
        reference(0x15829, 0x15697, RefType.DATA);
        completeFunction(0x55d98, 0x55deb, 6, 41);
        completeFunction(0x55deb, 0x55e5b, 6, 53);
        completeFunction(0x56713, 0x567a6, 6, 60);
        var nearCall = currentProgram.getListing().getInstructionAt(context.mapped(0x55dc6));
        require(nearCall != null && nearCall.getFlowType().isCall() && nearCall.getLength() == 3, "Dispatcher must own actual FF5402 near indirect CALL, not FAR-cell inference");
        originalBytes(0x55e3d, "8a85986d");
        originalBytes(0x56718, "c606ed1a01");
        originalBytes(0x56745, "c606ed1a00");
        require(comment(0x55deb).contains("RESTORES") && comment(0x55deb).contains("conflicts"), "Dot restoration direction and incompatible zero-row/nonzero-dot guards must remain explicit");

        // R160 actual52 singleton nonadditive movable records: native relocation -> loaded FAR -> DATA reference.
        callbacks(0x19574);
        callbacks(0x1965a);
        movableReference(0x1959c, 0x02bb, 0x8ecb3);
        movableReference(0x19682, 0x02dd, 0x92b33);
        completeFunction(0x8eae6, 0x8eb6d, 4, 52);
        completeFunction(0x92312, 0x9243c, 4, 105);
        require(comment(0x8ecb3).contains("not a complete function") && comment(0x92b33).contains("not a complete function"), "Computed-dispatch callback prefixes must stay partial");
        require(comment(0x19574).contains("DF=0") && comment(0x19574).contains("No local CLD"), "Forward table installation must not assume DF after opaque helper");

        // R143 actual append/counter distinction, five separate descriptors and real calls.
        structure("WordArrayAppendDescriptor8Partial", 8, new int[] { 0, 2, 4 }, new int[] { 2, 2, 2 });
        for (long descriptor : new long[] { 0x1c471, 0x1c3ca, 0x1c3c2, 0x1c3ba, 0x1c3b2 }) {
            var data = currentProgram.getListing().getDefinedDataAt(context.mapped(descriptor));
            require(data != null && data.getDataType() instanceof Structure && data.getLength() == 8, "Five independent WORD append descriptors must remain distinct native data");
        }
        completeFunction(0x7241a, 0x724ac, 6, 56);
        completeFunction(0x7a0b0, 0x7a177, 10, 69);
        completeFunction(0x804b4, 0x80548, 4, 58);
        reference(0x7a0bc, 0x7241a, RefType.DATA);
        var appendCall = currentProgram.getListing().getInstructionAt(context.mapped(0x7a0bb));
        require(appendCall != null && Arrays.asList(appendCall.getFlows()).contains(context.mapped(0x7241a)), "Actual node CALL must resolve to native NE51:121a, not a raw placeholder");
        require(comment(0x7a0b0).contains("no U=2*C"), "Allocation offset and returned counter correspondence must not be invented");

        // R168 real unaligned descriptor field and corrected full RET immediate.
        originalBytes(0x18092, "2955fe00c1030002020a0a0a00000029002d00");
        var descriptor = currentProgram.getListing().getDefinedDataAt(context.mapped(0x18092));
        require(descriptor != null && descriptor.getLength() == 19 && ((ghidra.program.model.scalar.Scalar) descriptor.getComponentContaining(3).getValue()).getUnsignedValue() == 0xc100, "SUB unaligned tested WORD+3 must be c100");
        require(Short.toUnsignedInt(currentProgram.getMemory().getShort(context.mapped(0x18096))) == 0x03c1, "Distinct overlapping WORD+4 must remain03c1, not moved tested field");
        completeFunction(0x8e49b, 0x8e4af, 2, 11);
        originalBytes(0x8e4ac, "c20200");
        require(currentProgram.getListing().getInstructionAt(context.mapped(0x8e4ac)).getLength() == 3, "Mapping RET2 must include final zero immediate byte00ae");
        completeFunction(0x8fb88, 0x8fce9, 6, 127);
        completeFunction(0x8fce9, 0x8fdbe, 2, 90);
        originalBytes(0x8f984, "c012");
        originalBytes(0x8fa0e, "810b");
        reference(0x8f984, 0x8f6c0, RefType.DATA);
        originalBytes(0x195dc, "000402060307010506070504");

        // R275 independent allocations/views and original tables, not synthetic generated events.
        structure("Event16Partial", 16, new int[] { 0, 2, 4, 6, 8, 10, 12, 14 }, new int[] { 2, 2, 2, 2, 2, 2, 2, 2 });
        structure("EventMetadata16Partial", 16, new int[] { 4, 8, 10 }, new int[] { 4, 2, 2 });
        structure("EventPending16Partial", 16, new int[] { 0, 10 }, new int[] { 2, 4 });
        var codes = currentProgram.getDataTypeManager().getDataType(Bcc31Profile.TYPES, "EventBranchCode");
        require(codes instanceof Enum && ((Enum) codes).getValue("JE") == 10 && ((Enum) codes).getValue("JNE") == 11, "Native event code domain must retain actual JE/JNE mapping");
        originalBytes(0x1947c, "d058d358");
        originalBytes(0x194d0, "6a65006a6e6500");
        originalBytes(0x194a2, "7475");
        originalBytes(0x19560, "0b000a00");
        reference(0x1947c, 0x194d0, RefType.DATA);
        completeFunction(0x73b30, 0x73ba8, 0, 43);
        completeFunction(0x7403d, 0x740ad, 6, 39);
        completeFunction(0x74b23, 0x74c4f, 4, 101);
        completeFunction(0x8b37f, 0x8b7c0, 8, 370);
        completeFunction(0x85200, 0x8543d, 4, 177);
        var switchTable = currentProgram.getListing().getDefinedDataAt(context.mapped(0x8543d));
        require(switchTable != null && switchTable.getLength() == 12 && switchTable.getDataType() instanceof Array, "Consumer adjacent switch WORDs must be native data, not function instructions");
        originalBytes(0x79b00, "26c744021000");
        movableReference(0x13cc2, 0xa, 0x3ee24);
        movableReference(0x13cca, 0x9, 0x480b1);
        completeFunction(0x3ee24, 0x3ee31, 4, 6);
        completeFunction(0x9400, 0x950b, 4, 88);
        require(comment(0x480b1).contains("not a complete function") && comment(0x480b1).contains("NOW-current"), "Transformer rewrite must retain partial extent and fresh-pointer mutation order");

        int typeCount = currentProgram.getDataTypeManager().getDataTypeCount(true);
        int symbols = currentProgram.getSymbolTable().getNumSymbols();
        String before = comment(0x55deb);
        rerun(profile, args[2].equals("automatic"), log);
        require(typeCount == currentProgram.getDataTypeManager().getDataTypeCount(true) && symbols == currentProgram.getSymbolTable().getNumSymbols() && before.equals(comment(0x55deb)), "Repeated profile must not duplicate native types, labels or comments");
        Function guarded = currentProgram.getFunctionManager().getFunctionAt(context.mapped(0x8e49b));
        guarded.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        guarded.setName("user_owned_bcc31_mapping", SourceType.USER_DEFINED);
        String signature = guarded.getPrototypeString(true, true);
        AddressSet body = new AddressSet(guarded.getBody());
        rerun(profile, args[2].equals("automatic"), log);
        require(signature.equals(guarded.getPrototypeString(true, true)) && body.equals(guarded.getBody()) && guarded.getSignatureSource() == SourceType.USER_DEFINED, "Actual user-owned signature/body must be preserved on repeated application");
        result.append(args[2].equals("automatic") ? "Reapplications used the production analyzer native batch.\n" : "Reapplications were explicitly direct; automatic batch behavior is not proved in this mode.\n");
        result.append("Native assertions passed: near/FAR separation,52 loaded source references,DF qualification,five arrays/counter,unaligned descriptor/full RET,event tables/views/extents,partial transformer,reapplication,user-source priority.\n");
        result.append(log).append('\n');
        Files.writeString(Path.of(args[1]).resolve("bcc31-profile-validation.txt"), result);
        println("BCC31 PROFILE VALIDATION PASS (" + args[2] + "): original bytes, native data/enum/reference/function outcomes and preservation. " + args[1]);
    }

    private void callbacks(long start) throws Exception {
        var data = currentProgram.getListing().getDefinedDataAt(context.mapped(start));
        require(data != null && data.getLength() == 104 && data.getDataType() instanceof Array && ((Array) data.getDataType()).getNumElements() == 26, "Expected26 native four-byte FAR storage cells");
        for (int i = 0; i < 26; i++) {
            Address cell = context.mapped(start + 4L * i);
            var records = currentProgram.getRelocationTable().getRelocations(cell);
            require(records.size() == 1, "Expected singleton native relocation");
            Relocation r = records.get(0);
            long[] values = r.getValues();
            require(r.getStatus() == Relocation.Status.APPLIED && r.getType() == 3 && values.length == 5 && values[0] == ((SegmentedAddress) currentProgram.getMemory().getBlock(cell).getStart()).getSegment() && values[1] == 0 && values[3] == 0xff, "Expected native loaded source segmentID (not ordinal9), separate type3 and internal movable target tuple");
            int offset = Short.toUnsignedInt(currentProgram.getMemory().getShort(cell));
            int selector = Short.toUnsignedInt(currentProgram.getMemory().getShort(cell.add(2)));
            Address loaded = ((SegmentedAddressSpace) cell.getAddressSpace()).getAddress(selector, offset);
            var reference = currentProgram.getReferenceManager().getReference(cell, loaded, 0);
            require(reference != null && reference.getReferenceType() == RefType.DATA, "Actual loaded FAR cell must have DATA reference, not fabricated CALL");
        }
        result.append("Native26-cell table FILE").append(Long.toHexString(start)).append(" passed loaded relocation/reference assertions.\n");
    }

    private void movableReference(long source, int ordinal, long target) {
        reference(source, target, RefType.DATA);
        require(currentProgram.getRelocationTable().getRelocations(context.mapped(source)).stream().anyMatch(r -> r.getType() == 3 && r.getValues().length == 5 && r.getValues()[3] == 0xff && r.getValues()[4] == ordinal), "Expected raw movable ordinal, not NE segment ordinal or imported paragraph");
    }

    private void reference(long source, long target, RefType type) {
        var reference = currentProgram.getReferenceManager().getReference(context.mapped(source), context.mapped(target), 0);
        require(reference != null && reference.getReferenceType() == type, "Missing native reference from FILE" + Long.toHexString(source));
    }

    private void rerun(Bcc31Profile profile, boolean automatic, MessageLog log) throws Exception {
        if (automatic) {
            require(new ToolchainProfileAnalyzer().added(currentProgram, currentProgram.getMemory(), monitor, log), "Production analyzer rerun failed: " + log);
        }
        else {
            profile.apply(context, monitor, log);
        }
    }

    private void completeFunction(long start, long end, int purge, int count) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(context.mapped(start));
        require(function != null && function.getBody().equals(context.range(start, end)) && function.getStackPurgeSize() == purge, "Incorrect evidenced complete extent/cleanup FILE" + Long.toHexString(start));
        int actual = 0;
        Address cursor = context.mapped(start);
        while (cursor.compareTo(context.mapped(end - 1)) <= 0) {
            var instruction = currentProgram.getListing().getInstructionAt(cursor);
            require(instruction != null && instruction.getMaxAddress().compareTo(context.mapped(end - 1)) <= 0, "Incomplete native instruction ownership at " + cursor);
            cursor = cursor.add(instruction.getLength());
            actual++;
        }
        require(actual == count, "Original-evidenced native instruction count mismatch at FILE" + Long.toHexString(start) + ":" + actual + " expected" + count);
        result.append("Complete FILE[").append(Long.toHexString(start)).append(',').append(Long.toHexString(end)).append(") native instructions=").append(actual).append(" purge=").append(purge).append('\n');
    }

    private void structure(String name, int length, int[] offsets, int[] sizes) {
        var type = currentProgram.getDataTypeManager().getDataType(Bcc31Profile.TYPES, name);
        require(type instanceof Structure && type.getLength() == length, "Missing native qualified partial structure " + name);
        for (int i = 0; i < offsets.length; i++) {
            var field = ((Structure) type).getComponentAt(offsets[i]);
            require(field != null && field.getOffset() == offsets[i] && field.getLength() == sizes[i], "Incorrect known partial field " + name + "+" + offsets[i]);
        }
    }

    private void originalBytes(long offset, String hex) throws Exception {
        byte[] expected = HexFormat.of().parseHex(hex);
        byte[] actual = new byte[expected.length];
        require(context.original().getOriginalBytes(offset, actual) == actual.length && Arrays.equals(expected, actual), "Contradictory original source bytes FILE" + Long.toHexString(offset));
    }

    private boolean hasLabel(long file, String name) {
        return currentProgram.getSymbolTable().getSymbol(name, context.mapped(file), currentProgram.getGlobalNamespace()) != null;
    }

    private String comment(long file) {
        return currentProgram.getListing().getComment(CommentType.PLATE, context.mapped(file));
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
