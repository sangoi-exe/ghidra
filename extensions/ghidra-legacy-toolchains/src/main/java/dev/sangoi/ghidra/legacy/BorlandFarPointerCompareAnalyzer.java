package dev.sangoi.ghidra.legacy;

import java.util.HexFormat;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** Complete F_PCMP member correspondence, without exclusive compiler-release attribution. */
public class BorlandFarPointerCompareAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland far pointer compare (qualified 16-bit)";
    public static final String CONVENTION = "borland_far_pointer_compare_16far";
    private static final byte[] BODY = HexFormat.of().parseHex("518ae8b104d3e803d08ac58ae3d3eb5903cb8adc250f0083e30f3bd175023bc3cb");
    private static final int[] INSTRUCTION_LENGTHS = { 1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 3, 3, 2, 2, 2, 1 };
    private static final String COMMENT = "[Qualified Borland far pointer compare]\n"
        + "Complete 33-byte/17-instruction body equals the retained CWM 3.1 F_PCMP member; exclusive release and historical source are not inferred.\n"
        + "Inputs are entry DX:AX and CX:BX words. AX=entryAX&15, DX=u16(entryDX+(entryAX>>4)), BX=entryBX&15, CX=u16(entryCX+(entryBX>>4)); shifts are logical. CX is not preserved.\n"
        + "CMP DX,CX supplies arithmetic flags when high words differ; otherwise CMP AX,BX does. Returned ZF means normalized high AND low words agree, not raw input-pair equality or nullness; AX is not boolean.\n"
        + "The nine-byte joined ZF/AX/DX/BX/CX result is analysis-only native storage, not a historical C ABI. Other arithmetic flags are clobbered here, not computed by the prototype.\n"
        + "BP/SI/DI/DS/ES/SS/DF not written; internal CX PUSH/POP balanced; plain RETF removes four return bytes and zero argument bytes. Ordinary intact-stack completion is assumed. No selector mapping, object purpose or downstream effects are inferred.";

    public BorlandFarPointerCompareAnalyzer() {
        super(NAME, "Recognize the complete F_PCMP correspondence and retain normalized register words plus returned ZF.", "qualified_borland_far_pointer_compare", CONVENTION, "borland-far-pointer-compare.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        var address = BorlandDataTypes.farAddress16(program);
        StructureDataType state = new StructureDataType(new CategoryPath("/LegacyToolchains/Borland"), "FarPointerCompareAnalysisState9", 0);
        state.setDescription("Analysis-only ZF/AX/DX/BX/CX tuple after the qualified finite-word comparison; not a historical C return type or raw pair equality.");
        state.add(BooleanDataType.dataType, "equal_zf", "Normalized high and low words both equal.");
        state.add(UnsignedShortDataType.dataType, "ax", "entryAX & 15; not boolean.");
        state.add(UnsignedShortDataType.dataType, "dx", "u16(entryDX + (entryAX >> 4)).");
        state.add(UnsignedShortDataType.dataType, "bx", "entryBX & 15.");
        state.add(UnsignedShortDataType.dataType, "cx", "u16(entryCX + (entryBX >> 4)); not preserved.");
        var result = program.getDataTypeManager().resolve(state, DataTypeConflictHandler.DEFAULT_HANDLER);
        var storage = new VariableStorage(program, program.getRegister("CX"), program.getRegister("BX"), program.getRegister("DX"), program.getRegister("AX"), program.getRegister("ZF"));
        function.updateFunction(CONVENTION, new ReturnParameterImpl(result, storage, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("entry_dx_ax", address, new VariableStorage(program, program.getRegister("DX"), program.getRegister("AX")), program, SourceType.ANALYSIS),
            new ParameterImpl("entry_cx_bx", address, new VariableStorage(program, program.getRegister("CX"), program.getRegister("BX")), program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_far_pointer_compare", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland far pointer compare]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
