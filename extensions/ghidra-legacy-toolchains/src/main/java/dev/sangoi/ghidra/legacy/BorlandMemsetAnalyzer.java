package dev.sangoi.ghidra.legacy;

import java.util.HexFormat;

import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;

/** The complete wrapper, including the literal PUSH CS / near CALL to the internal fill body. */
public class BorlandMemsetAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland memset (qualified 16-bit)";
    public static final String CONVENTION = "borland_memset_16far";
    private static final byte[] BODY = HexFormat.of().parseHex("45558bec568b76068a460850ff760a560ee8c4ff83c4068bc65e5d4dcb");
    private static final int[] INSTRUCTION_LENGTHS = { 1, 1, 2, 1, 3, 3, 1, 3, 1, 1, 3, 3, 2, 1, 1, 1, 1 };
    private static final String COMMENT = "[Qualified Borland memset]\n"
        + "Complete 29-byte wrapper corresponds to _memset at CWM 3.1 MEMSET _TEXT:0028, adjoining its 40-byte _setmem body. No exclusive compiler release or historical C declaration is inferred.\n"
        + "Analysis inputs are WORDs at entry SP+4/+6/+8: DS-selected destination offset, value word (only low byte read), unsigned byte count. Offset storage is not a flat/host pointer or a proof of selector mapping.\n"
        + "PUSH CS then E8C4FF creates the four-byte far-compatible return frame for the internal body 40 bytes before this entry. Wrapper pushes value/count/destination WORDs and removes those six bytes after the inner RETF. Its own plain RETF also leaves six caller-owned argument bytes: purge0, far return4.\n"
        + "After the inner call, MOV AX,SI returns current SI before POP SI restores the saved register; this is an AX WORD observation, not unrestricted initial-pointer or historical C memset-return semantics.\n"
        + "The fill body is separately qualified; only when that target is the evidenced internal body and frames/accesses are non-disruptive, ES=DS, CX=0, DF=0, BP/SI/DI restored, BX/DX/DS untouched, SS not written. Upper-register behavior, arbitrary aliases, selector validity and faults are not generalized.\n"
        + "ADD SP,6 overwrites flags from the fill; final DEC BP sets arithmetic flags except CF, which remains from that ADD. No flag preservation is asserted. Prototype clobbers do not compute output values or model fill memory effects.\n"
        + "Observed original outer caller uses PUSH CS/near CALL, ADD SP,6, then overwrites AX with 3; this proves caller cleanup, not consumption of the AX result.";

    public BorlandMemsetAnalyzer() {
        super(NAME, "Recognize the complete evidenced fill wrapper and its WORD result without modern pointer semantics.", "qualified_borland_memset", CONVENTION, "borland-memset.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        BorlandSetmemAnalyzer.requireQualifiedTarget(program, function.getEntryPoint().subtract(40));
        function.updateFunction(CONVENTION, new ReturnParameterImpl(UnsignedShortDataType.dataType, program.getRegister("AX"), program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("destination_offset", UnsignedShortDataType.dataType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("value_word_low_byte", UnsignedShortDataType.dataType, 6, program, SourceType.ANALYSIS),
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, 8, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_memset", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland memset]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
