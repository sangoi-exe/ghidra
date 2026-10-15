package dev.sangoi.ghidra.legacy;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** Recognizes only the complete shared BCC 3.1/4.5 helper body, without identifying a compiler release. */
public class BorlandFScopyAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String CONVENTION = "borland_f_scopy_16far";
    public static final String NAME = "Borland F_SCOPY (qualified 16-bit)";

    private static final byte[] BODY = {
        0x55, (byte) 0x8b, (byte) 0xec, 0x56, 0x57, 0x1e, (byte) 0xc5, 0x76,
        0x06, (byte) 0xc4, 0x7e, 0x0a, (byte) 0xfc, (byte) 0xd1, (byte) 0xe9,
        (byte) 0xf3, (byte) 0xa5, 0x13, (byte) 0xc9, (byte) 0xf3, (byte) 0xa4,
        0x1f, 0x5f, 0x5e, 0x5d, (byte) 0xca, 0x08, 0x00
    };
    private static final int[] INSTRUCTION_LENGTHS = { 1, 2, 1, 1, 1, 3, 3, 1, 2, 2, 2, 2, 1, 1, 1, 1, 3 };
    private static final String COMMENT = "[Qualified Borland F_SCOPY]\n"
        + "Complete 28-byte body shared by supplied BCC 3.1 and 4.5 objects; no exclusive compiler identification.\n"
        + "Analysis inputs: CX = unsigned 16-bit byte count; source offset/selector at entry SP+4/+6; destination offset/selector at SP+8/+10.\n"
        + "FarAddress16 is an offset/selector storage record, not a recovered C type or proof of selector-to-address mapping.\n"
        + "RETF 8: 8 argument bytes purged, 4-byte far return, total entry-SP delta 12. No manufactured scalar return value; analysis void is not a historical C declaration.\n"
        + "On ordinary completion with valid, non-disruptive storage: BP/SI/DI/DS restored; AX/BX/DX untouched; SS not written; ES = destination selector; CX = 0; DF = 0.\n"
        + "Forward word copies then odd-byte tail; not memmove. Prototype clobbers ES/CX/DF but does not compute those post-call values or model copy memory effects.";

    public BorlandFScopyAnalyzer() {
        super(NAME, "Recognize the complete evidenced F_SCOPY body and apply its implicit CX and far-frame contract.", "F_SCOPY", CONVENTION, "borland-f-scopy.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        DataType addressType = BorlandDataTypes.farAddress16(program);
        function.updateFunction(CONVENTION, new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, program.getRegister("CX"), program, SourceType.ANALYSIS),
            new ParameterImpl("source", addressType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("destination", addressType, 8, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(8);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("F_SCOPY", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland F_SCOPY]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
