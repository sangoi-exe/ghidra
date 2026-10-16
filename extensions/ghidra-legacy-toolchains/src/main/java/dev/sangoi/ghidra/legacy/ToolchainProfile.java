package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
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
        public Function function(long start, long endExclusive, String name, int purge, String qualification) throws Exception {
            return function(start, range(start, endExclusive), name, purge, qualification + " Complete original-file extent [" + Long.toHexString(start) + "," + Long.toHexString(endExclusive) + ")");
        }

        /** Qualified native code body; separate ranges can exclude a genuinely independent entry. */
        public Function function(long start, AddressSet body, String name, int purge, String qualification) throws Exception {
            Address entry = mapped(start);
            if (!body.contains(entry)) {
                throw new IllegalArgumentException("Qualified function body must contain its original-file entry");
            }
            var manager = program.getFunctionManager();
            for (Function existing : overlapping(body)) {
                if (existing.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || existing.getSymbol().getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    comment(start, "Preserved higher-priority function/signature; qualified native body " + body + ". " + qualification);
                    return existing;
                }
            }
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
            return function;
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
