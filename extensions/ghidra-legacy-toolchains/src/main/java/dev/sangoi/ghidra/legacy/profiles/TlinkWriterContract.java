package dev.sangoi.ghidra.legacy.profiles;

import java.nio.charset.StandardCharsets;

import dev.sangoi.ghidra.legacy.ToolchainProfile;
import ghidra.framework.Application;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** The established common 150-byte writers' native output storage and near-stack model. */
public final class TlinkWriterContract {
    public static final String CONVENTION = "tlink_writer_state_16near";
    public static final CategoryPath TYPES = new CategoryPath("/LegacyToolchains/TLINK");

    private TlinkWriterContract() {
    }

    public static void apply(ToolchainProfile.Context c, Function function, TaskMonitor monitor) throws Exception {
        if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || function.getSymbol().getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
            return;
        }
        var program = c.program();
        String xml;
        try (var input = Application.getModuleDataFile("tlink-writer-state.xml").getInputStream()) {
            xml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        if (!xml.equals(SpecExtension.getCompilerSpecExtension(program, SpecExtension.Type.PROTOTYPE_MODEL, CONVENTION))) {
            new SpecExtension(program).addReplaceCompilerSpecExtension(xml, monitor);
        }
        StructureDataType state = new StructureDataType(TYPES, "NearWriterAnalysisState7", 0);
        state.setDescription("Analysis-only joined result: actual CF, DX, CX and ES at ordinary near RET. Not historical C, independent multiple-result ABI, physical-I/O success or selector validity. Preservation assumes intact stack/selected views; caller propagation requires separate evidence.");
        state.add(BooleanDataType.dataType, "accepted_cf", "CF1 only on the qualified rewrite; rejection CF0.");
        state.add(UnsignedShortDataType.dataType, "dx", "Success u16(entryDX+F802); rejection unchanged.");
        state.add(UnsignedShortDataType.dataType, "cx", "Success u16(entryCX-j-4-current record offset); rejection unchanged.");
        state.add(UnsignedShortDataType.dataType, "es", "Final descriptor-array selector, not preserved incoming ES.");
        var result = program.getDataTypeManager().resolve(state, DataTypeConflictHandler.DEFAULT_HANDLER);
        var storage = new VariableStorage(program, program.getRegister("ES"), program.getRegister("CX"), program.getRegister("DX"), program.getRegister("CF"));
        // These are demonstrated native entry words, not recovered historical C parameters.
        function.updateFunction(CONVENTION, new ReturnParameterImpl(result, storage, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("entry_bx", UnsignedShortDataType.dataType, program.getRegister("BX"), program, SourceType.ANALYSIS),
            new ParameterImpl("entry_cx", UnsignedShortDataType.dataType, program.getRegister("CX"), program, SourceType.ANALYSIS),
            new ParameterImpl("entry_dx", UnsignedShortDataType.dataType, program.getRegister("DX"), program, SourceType.ANALYSIS),
            new ParameterImpl("entry_ds", UnsignedShortDataType.dataType, program.getRegister("DS"), program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        // Imported constant DS is loader context, not this helper's caller-qualified DS.
        program.getProgramContext().remove(function.getBody().getMinAddress(), function.getBody().getMaxAddress(), program.getRegister("DS"));
        String comment = "[TLINK writer analysis contract] Complete 51-instruction/150-byte near body; BX/CX/DX plus current DS-selected memory are inputs. AX/SI/DI are saved/restored; BX/BP/DS/SS/CS/DF untouched locally; SP has ordinary near-return delta2, argument purge0. ES is overwritten by the two selected arrays; CX/DX change only on accepted rewrite. Other arithmetic flags are clobbered, not preserved. CF/DX/CX/ES are retained as a seven-byte analysis tuple, not recovered historical C or a universal caller ABI. Default __cdecl16near would incorrectly preserve ES. Memory/stack extents, selector validity, alias-sensitive ordering, caller propagation and physical effects remain unproved.";
        String previous = function.getComment();
        if (previous == null || !previous.contains(comment)) {
            function.setComment(previous == null ? comment : previous + "\n\n" + comment);
        }
    }
}
