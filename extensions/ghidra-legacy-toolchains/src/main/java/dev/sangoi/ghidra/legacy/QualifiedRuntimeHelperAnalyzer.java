package dev.sangoi.ghidra.legacy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Shared native recognition path for complete, independently qualified 16-bit runtime helpers. */
public abstract class QualifiedRuntimeHelperAnalyzer extends AbstractAnalyzer {
    private final String analyzerName;
    private final String functionName;
    private final String convention;
    private final String prototypeAsset;
    private final byte[] bodyBytes;
    private final int[] instructionLengths;

    protected QualifiedRuntimeHelperAnalyzer(String name, String description, String functionName, String convention, String prototypeAsset, byte[] bodyBytes, int[] instructionLengths) {
        super(name, description, AnalyzerType.BYTE_ANALYZER);
        this.analyzerName = name;
        this.functionName = functionName;
        this.convention = convention;
        this.prototypeAsset = prototypeAsset;
        this.bodyBytes = bodyBytes.clone();
        this.instructionLengths = instructionLengths.clone();
        // Native segmented convention analysis otherwise replaces named conventions from RETF alone.
        setPriority(AnalysisPriority.LOW_PRIORITY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        String language = program.getLanguageID().toString();
        return language.equals("x86:LE:16:Protected Mode") || language.equals("x86:LE:16:Real Mode");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        boolean installed = false;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            AddressSet search = new AddressSet(block.getStart(), block.getEnd()).intersect(set);
            for (var range : search) {
                Address next = range.getMinAddress();
                while (next != null && next.compareTo(range.getMaxAddress()) <= 0) {
                    monitor.checkCancelled();
                    Address match = program.getMemory().findBytes(next, range.getMaxAddress(), bodyBytes, null, true, monitor);
                    if (match == null) {
                        break;
                    }
                    next = match.next();
                    Address end = match.add(bodyBytes.length - 1);
                    if (end.compareTo(block.getEnd()) > 0) {
                        continue;
                    }
                    Function containing = program.getFunctionManager().getFunctionContaining(match);
                    if (containing != null && (!containing.getEntryPoint().equals(match)
                            || containing.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS))) {
                        log.appendMsg(analyzerName, "Preserving existing function/signature at " + match);
                        continue;
                    }
                    try {
                        AddressSet body = new AddressSet(match, end);
                        DisassembleCommand disassembly = new DisassembleCommand(match, body, true);
                        disassembly.enableCodeAnalysis(false);
                        if (!disassembly.applyTo(program, monitor) || !hasQualifiedInstructions(program, match, instructionLengths)) {
                            log.appendMsg(analyzerName, "Complete bytes at " + match + " do not have the qualified native instruction boundaries");
                            continue;
                        }
                        Function function = containing;
                        if (function == null) {
                            function = program.getFunctionManager().createFunction(functionName, match, body, SourceType.ANALYSIS);
                        }
                        if (!installed) {
                            installConvention(program, monitor);
                            installed = true;
                        }
                        applyContract(program, function);
                        log.appendMsg(analyzerName, "Applied qualified " + functionName + " contract at " + match);
                    }
                    catch (CancelledException e) {
                        throw e;
                    }
                    catch (Exception e) {
                        log.appendMsg(analyzerName, "Failed to apply " + functionName + " at " + match + ": " + e.getMessage());
                        log.appendException(e);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    protected static boolean hasQualifiedInstructions(Program program, Address entry, int[] instructionLengths) {
        Address address = entry;
        for (int length : instructionLengths) {
            Instruction instruction = program.getListing().getInstructionAt(address);
            if (instruction == null || instruction.getLength() != length) {
                return false;
            }
            // Context can override a language's default size at any instruction, not only entry.
            for (String name : new String[] { "opsize", "addrsize" }) {
                var value = program.getProgramContext().getValue(program.getRegister(name), address, false);
                if (value == null || value.signum() != 0) {
                    return false;
                }
            }
            address = address.add(length);
        }
        return true;
    }

    private void installConvention(Program program, TaskMonitor monitor) throws Exception {
        String xml;
        try (var input = Application.getModuleDataFile(prototypeAsset).getInputStream()) {
            xml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            throw new IOException("Missing native " + functionName + " prototype asset", e);
        }
        if (!xml.equals(SpecExtension.getCompilerSpecExtension(program, SpecExtension.Type.PROTOTYPE_MODEL, convention))) {
            new SpecExtension(program).addReplaceCompilerSpecExtension(xml, monitor);
        }
    }

    protected abstract void applyContract(Program program, Function function) throws Exception;
}
