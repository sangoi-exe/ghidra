package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.ne.NewExecutable;
import ghidra.app.util.bin.format.ne.WindowsHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MzLoader;
import ghidra.app.util.opinion.NeLoader;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Exact-image facts, with shared native provenance and conservative Program editing. */
public abstract class ToolchainProfile {
    private final String id;
    private final String format;
    private final long size;
    private final String sha256;

    protected ToolchainProfile(String id, String executableFormat, long originalSize, String sha256) {
        this.id = id;
        this.format = executableFormat;
        this.size = originalSize;
        this.sha256 = sha256;
    }

    public final String id() {
        return id;
    }

    /** Uses original FileBytes, never the relocated memory or the current executable path. */
    public final Context match(Program program, TaskMonitor monitor) throws Exception {
        if (!format.equals(program.getExecutableFormat())) {
            return null;
        }
        for (FileBytes bytes : program.getMemory().getAllFileBytes()) {
            if (bytes.getFileOffset() != 0 || bytes.getSize() != size) {
                continue;
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[65536];
            for (long offset = 0; offset < size;) {
                monitor.checkCancelled();
                int length = (int) Math.min(buffer.length, size - offset);
                if (bytes.getOriginalBytes(offset, buffer, 0, length) != length) {
                    throw new IOException("Incomplete original FileBytes for " + id);
                }
                digest.update(buffer, 0, length);
                offset += length;
            }
            if (sha256.equals(HexFormat.of().formatHex(digest.digest()))) {
                return new Context(program, bytes, id, monitor);
            }
        }
        return null;
    }

    /** Qualified data, datatype preparation and necessary native address projections, before inference. */
    public abstract void prepareData(Context context, TaskMonitor monitor, MessageLog log) throws Exception;

    /** Final qualified code extents, cleanup and function contracts, after ordinary analysis. */
    public abstract void applyFinalFacts(Context context, TaskMonitor monitor, MessageLog log) throws Exception;

    /** Dependent mutations may run only when the qualified function facts were applied. */
    public record FunctionApplication(Function function, boolean applied) {
    }

    public static final class Context {
        private final Program program;
        private final FileBytes original;
        private final String marker;
        private final TaskMonitor monitor;

        private Context(Program program, FileBytes original, String id, TaskMonitor monitor) {
            this.program = program;
            this.original = original;
            this.marker = "[LegacyToolchains " + id + "]";
            this.monitor = monitor;
        }

        public Program program() {
            return program;
        }

        public FileBytes original() {
            return original;
        }

        public Address mapped(long fileOffset) {
            var addresses = program.getMemory().locateAddressesForFileBytesOffset(original, fileOffset);
            if (addresses.size() != 1) {
                throw new IllegalStateException(marker + " required original FILE " + Long.toHexString(fileOffset) + " has " + addresses.size() + " mappings: " + addresses);
            }
            return addresses.get(0);
        }

        public AddressSet range(long start, long endExclusive) {
            if (endExclusive <= start) {
                throw new IllegalArgumentException("Empty or reversed original-file range");
            }
            Address first = mapped(start);
            // Native loaders may split a physically contiguous original range across adjacent blocks, even inside an instruction. Verify the complete file/address relationship, not block identity or endpoints alone.
            for (long fileOffset = start + 1; fileOffset < endExclusive; fileOffset++) {
                if (!first.add(fileOffset - start).equals(mapped(fileOffset))) {
                    throw new IllegalStateException(marker + " noncontiguous required file mapping at FILE " + Long.toHexString(fileOffset));
                }
            }
            return new AddressSet(first, first.add(endExclusive - start - 1));
        }

        public void label(long fileOffset, String name) throws Exception {
            Address address = mapped(fileOffset);
            var symbols = program.getSymbolTable();
            if (symbols.getSymbol(name, address, program.getGlobalNamespace()) == null) {
                symbols.createLabel(address, name, SourceType.ANALYSIS);
            }
        }

        public void comment(long fileOffset, String text) {
            Address address = mapped(fileOffset);
            String addition = marker + " " + text;
            String previous = program.getListing().getComment(CommentType.PLATE, address);
            if (previous == null || !previous.contains(addition)) {
                program.getListing().setComment(address, CommentType.PLATE, previous == null ? addition : previous + "\n\n" + addition);
            }
        }

        private List<Function> overlapping(AddressSet range) {
            List<Function> result = new ArrayList<>();
            program.getFunctionManager().getFunctionsOverlapping(range).forEachRemaining(result::add);
            return result;
        }

        private void requireAnalysisOwned(AddressSet range) throws CancelledException {
            for (var symbol : program.getSymbolTable().getSymbolIterator(range.getMinAddress(), true)) {
                if (symbol.getAddress().compareTo(range.getMaxAddress()) > 0) {
                    break;
                }
                monitor.checkCancelled();
                if (symbol.getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    throw new IllegalStateException(marker + " preserving higher-priority symbol at " + symbol.getAddress());
                }
            }
            for (Function function : overlapping(range)) {
                if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || function.getSymbol().getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    throw new IllegalStateException(marker + " preserving higher-priority signature at " + function.getEntryPoint());
                }
            }
        }

        public void data(long fileOffset, DataType type) throws Exception {
            AddressSet body = range(fileOffset, fileOffset + type.getLength());
            var listing = program.getListing();
            var existing = listing.getDefinedDataAt(body.getMinAddress());
            if (existing != null && existing.getLength() == type.getLength() && existing.getDataType().isEquivalent(type)) {
                return;
            }
            // Native clearing removes whole intersecting units, including one starting before body.
            AddressSet affected = new AddressSet(body);
            var first = listing.getCodeUnitContaining(body.getMinAddress());
            var last = listing.getCodeUnitContaining(body.getMaxAddress());
            if (first != null) {
                affected.addRange(first.getMinAddress(), first.getMaxAddress());
            }
            if (last != null) {
                affected.addRange(last.getMinAddress(), last.getMaxAddress());
            }
            requireAnalysisOwned(affected);
            var conflicts = listing.getDefinedData(affected, true);
            if (conflicts.hasNext()) {
                var conflict = conflicts.next();
                // Defined data has no source-priority ownership. Original identity is not overwrite permission.
                throw new IllegalStateException(marker + " preserving conflicting defined data " + conflict.getDataType().getPathName() + " at " + conflict.getMinAddress() + " through " + conflict.getMaxAddress());
            }
            for (Function function : overlapping(affected)) {
                // Exact original data is authoritative over auto-created code, not user functions.
                program.getFunctionManager().removeFunction(function.getEntryPoint());
            }
            listing.clearCodeUnits(body.getMinAddress(), body.getMaxAddress(), false);
            listing.createData(body.getMinAddress(), type);
        }

        /** Complete evidenced extent and cleanup only; no inferred parameter/return prototype. */
        public FunctionApplication function(long start, long endExclusive, String name, int purge, String qualification) throws Exception {
            return function(start, range(start, endExclusive), name, purge, qualification + " Complete original-file extent [" + Long.toHexString(start) + "," + Long.toHexString(endExclusive) + ")");
        }

        /** Qualified native code body; separate ranges can exclude a genuinely independent entry. */
        public FunctionApplication function(long start, AddressSet body, String name, int purge, String qualification) throws Exception {
            Address entry = mapped(start);
            if (!body.contains(entry)) {
                throw new IllegalArgumentException("Qualified function body must contain its original-file entry");
            }
            var manager = program.getFunctionManager();
            for (Function existing : overlapping(body)) {
                if (existing.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || existing.getSymbol().getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    comment(start, "Preserved higher-priority function/signature; qualified native body " + body + ". " + qualification);
                    return new FunctionApplication(existing, false);
                }
            }
            requireCurrentCode(body);
            Function function = manager.getFunctionAt(entry);
            for (Function existing : overlapping(body)) {
                if (existing != function) {
                    manager.removeFunction(existing.getEntryPoint());
                }
            }
            DisassembleCommand command = new DisassembleCommand(entry, body, true);
            command.enableCodeAnalysis(false);
            if (!command.applyTo(program, monitor)) {
                throw new IllegalStateException(marker + " disassembly failed at " + entry + ": " + command.getStatusMsg());
            }
            for (var part : body) {
                Address cursor = part.getMinAddress();
                while (cursor.compareTo(part.getMaxAddress()) <= 0) {
                    monitor.checkCancelled();
                    var instruction = program.getListing().getInstructionAt(cursor);
                    if (instruction == null) {
                        DisassembleCommand remainder = new DisassembleCommand(cursor, body, false);
                        remainder.enableCodeAnalysis(false);
                        remainder.applyTo(program, monitor);
                        instruction = program.getListing().getInstructionAt(cursor);
                    }
                    if (instruction == null || instruction.getMaxAddress().compareTo(part.getMaxAddress()) > 0) {
                        throw new IllegalStateException(marker + " incomplete native instruction extent at " + cursor);
                    }
                    cursor = cursor.add(instruction.getLength());
                }
            }
            if (function == null) {
                function = manager.createFunction(name, entry, body, SourceType.ANALYSIS);
            }
            else {
                function.setBody(body);
                if (function.getSymbol().getSource() == SourceType.DEFAULT) {
                    function.setName(name, SourceType.ANALYSIS);
                }
            }
            function.setStackPurgeSize(purge);
            String cleanup = purge == Function.UNKNOWN_STACK_DEPTH_CHANGE ? "unknown" : purge + " argument bytes";
            comment(start, qualification + "; cleanup " + cleanup + ", not total return-frame delta. No stronger prototype or callee preservation inferred.");
            return new FunctionApplication(function, true);
        }

        private IllegalStateException unqualified(Address address, String reason) {
            return new IllegalStateException(marker + " preserving current code at " + address + ": " + reason + "; original identity does not qualify current function facts");
        }

        private long originalOffset(Address address) {
            var info = program.getMemory().getAddressSourceInfo(address);
            if (info == null || !original.equals(info.getMemoryBlockSourceInfo().getFileBytes().orElse(null)) || info.getFileOffset() < 0 || info.getFileOffset() >= original.getSize()) {
                throw unqualified(address, "missing qualified original-file provenance");
            }
            return info.getFileOffset();
        }

        private void requireCurrentCode(AddressSet body) throws Exception {
            // Build only this body's expected loader-written fields, never a baseline from current operands.
            Map<Address, Byte> relocated = new HashMap<>();
            WindowsHeader ne = null;
            var relocations = program.getRelocationTable().getRelocations();
            while (relocations.hasNext()) {
                monitor.checkCancelled();
                Relocation relocation = relocations.next();
                Address source = relocation.getAddress();
                int length = relocation.getLength();
                if (length == 0) {
                    if (body.contains(source)) {
                        throw unqualified(source, "unknown relocation width");
                    }
                    continue;
                }
                Address end = source.add(length - 1);
                if (!body.intersects(source, end)) {
                    continue;
                }
                if (!body.contains(source, end) || relocation.getStatus() != Relocation.Status.APPLIED) {
                    throw unqualified(source, "incomplete or unapplied relocation field");
                }
                if (NeLoader.NE_NAME.equals(program.getExecutableFormat()) && ne == null) {
                    ne = new NewExecutable(new FileBytesProvider(original), null).getWindowsHeader();
                }
                long expected = expectedRelocation(relocation, ne);
                for (int i = 0; i < length; i++) {
                    Address address = source.add(i);
                    originalOffset(address);
                    if (relocated.put(address, (byte) (expected >>> (8 * i))) != null) {
                        throw unqualified(address, "overlapping relocation fields");
                    }
                }
            }
            var context = program.getProgramContext();
            var operandSize = program.getRegister("opsize");
            var addressSize = program.getRegister("addrsize");
            if (operandSize == null || addressSize == null) {
                throw unqualified(body.getMinAddress(), "missing effective 16-bit context registers");
            }
            for (Address address : body.getAddresses(true)) {
                monitor.checkCancelled();
                long offset = originalOffset(address);
                byte expected = relocated.containsKey(address) ? relocated.get(address) : original.getOriginalByte(offset);
                if (program.getMemory().getByte(address) != expected) {
                    throw unqualified(address, "current byte differs from original/native relocation expectation at FILE " + Long.toHexString(offset));
                }
                if (!BigInteger.ZERO.equals(context.getValue(operandSize, address, false)) || !BigInteger.ZERO.equals(context.getValue(addressSize, address, false))) {
                    throw unqualified(address, "effective operand/address context is not 16-bit");
                }
            }
        }

        private long expectedRelocation(Relocation relocation, WindowsHeader ne) throws Exception {
            Address source = relocation.getAddress();
            long[] values = relocation.getValues();
            int type = relocation.getType();
            int length = relocation.getLength();
            // MzLoader records the actual loaded WORD independently of the operand's current value.
            if (MzLoader.MZ_NAME.equals(program.getExecutableFormat()) && type == 0 && length == 2 && values != null && values.length == 3 && values[2] >= 0 && values[2] <= 0xffff) {
                return values[2];
            }
            // These are the evidenced NeLoader classes. Selector writes ignore additive, unlike FAR writes.
            if (ne == null || values == null || values.length != 5 || !((type == 3 && length == 4 && (values[1] == 0 || values[1] == 1)) || (type == 2 && length == 2 && (values[1] == 0 || values[1] == 4)) || (type == 5 && length == 2 && values[1] == 0))) {
                throw unqualified(source, "unsupported native relocation evidence");
            }
            SegmentedAddress target;
            int targetSegment = (int) values[3] & 0xffff;
            int targetOffset = (int) values[4] & 0xffff;
            if (values[1] == 1) {
                var modules = ne.getModuleReferenceTable().getNames();
                if (targetSegment < 1 || targetSegment > modules.length) {
                    throw unqualified(source, "invalid import module ordinal");
                }
                String library = modules[targetSegment - 1].getString();
                String name = SymbolUtilities.ORDINAL_PREFIX + targetOffset;
                var locations = program.getExternalManager().getExternalLocations(library);
                List<Function> matches = new ArrayList<>();
                while (locations.hasNext()) {
                    var location = locations.next();
                    if (name.equals(location.getLabel()) || name.equals(location.getOriginalImportedName())) {
                        Function function = location.getFunction();
                        if (function == null) {
                            throw unqualified(source, "import is not a native external function");
                        }
                        matches.add(function);
                    }
                }
                if (matches.size() != 1) {
                    throw unqualified(source, "import identity is not unique: " + library + "!" + name);
                }
                Address[] thunks = matches.get(0).getFunctionThunkAddresses(false);
                if (thunks == null || thunks.length != 1 || !(thunks[0] instanceof SegmentedAddress segmented)) {
                    throw unqualified(source, "import does not have one direct native segmented thunk");
                }
                target = segmented;
            }
            else {
                if (targetSegment == 0xff) {
                    int ordinal = 1;
                    boolean found = false;
                    for (var bundle : ne.getEntryTable().getBundles()) {
                        int count = Byte.toUnsignedInt(bundle.getCount());
                        if (targetOffset >= ordinal && targetOffset < ordinal + count) {
                            if (bundle.getType() == 0 || bundle.isConstant()) {
                                throw unqualified(source, "movable target is an unused/constant entry");
                            }
                            var entry = bundle.getEntryPoints()[targetOffset - ordinal];
                            targetSegment = Byte.toUnsignedInt(bundle.isMoveable() ? entry.getSegment() : bundle.getType());
                            targetOffset = Short.toUnsignedInt(entry.getOffset());
                            found = true;
                            break;
                        }
                        ordinal += count;
                    }
                    if (!found) {
                        throw unqualified(source, "missing movable target entry");
                    }
                }
                var segments = ne.getSegmentTable().getSegments();
                if (targetSegment < 1 || targetSegment > segments.length) {
                    throw unqualified(source, "invalid internal segment ordinal");
                }
                var segment = segments[targetSegment - 1];
                int size = Short.toUnsignedInt(segment.getLength());
                if (segment.getOffsetShiftAligned() == 0 || targetOffset >= (size == 0 ? 0x10000 : size)) {
                    throw unqualified(source, "internal target is not original-file backed");
                }
                Address mappedTarget = mapped(Integer.toUnsignedLong(segment.getOffsetShiftAligned()) + targetOffset);
                if (!(mappedTarget instanceof SegmentedAddress segmented)) {
                    throw unqualified(source, "internal target is not a native segmented mapping");
                }
                target = segmented;
            }
            return switch (type) {
                case 2 -> target.getSegment();
                case 5 -> target.getSegmentOffset();
                default -> ((long) target.getSegment() << 16) | target.getSegmentOffset();
            };
        }

        /**
         * Joins an applied internal singleton/nonadditive NE FAR relocation to its qualified file target.
         * Raw target fields are either a direct NE table ordinal/offset or ff/movable-entry ordinal;
         * they are never loader-assigned paragraphs. Native loader relocation supplies the loaded pair.
         */
        public void farReference(long sourceFileOffset, int rawTargetSegment, int rawTargetOffset, long targetFileOffset) throws Exception {
            Address source = mapped(sourceFileOffset);
            Address target = mapped(targetFileOffset);
            boolean qualified = false;
            for (Relocation relocation : program.getRelocationTable().getRelocations(source)) {
                long[] values = relocation.getValues();
                if (relocation.getStatus() == Relocation.Status.APPLIED && relocation.getType() == 3 && values != null && values.length == 5 && values[1] == 0 && (values[3] & 0xffff) == rawTargetSegment && (values[4] & 0xffff) == rawTargetOffset) {
                    qualified = true;
                }
            }
            if (original.getOriginalByte(sourceFileOffset) != (byte) 0xff || original.getOriginalByte(sourceFileOffset + 1) != (byte) 0xff) {
                throw new IllegalStateException(marker + " source is not the qualified singleton chain terminator at " + source);
            }
            if (!qualified) {
                throw new IllegalStateException(marker + " missing applied singleton nonadditive NE FAR relocation at " + source);
            }
            int offset = Short.toUnsignedInt(program.getMemory().getShort(source));
            int selector = Short.toUnsignedInt(program.getMemory().getShort(source.add(2)));
            var space = (ghidra.program.model.address.SegmentedAddressSpace) target.getAddressSpace();
            if (!space.getAddress(selector, offset).equals(target)) {
                throw new IllegalStateException(marker + " native relocation/file target disagreement at " + source);
            }
            program.getReferenceManager().addMemoryReference(source, target, RefType.DATA, SourceType.ANALYSIS, 0);
        }
    }
}
