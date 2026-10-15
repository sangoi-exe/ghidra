package dev.sangoi.ghidra.legacy;

import java.util.HexFormat;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** The complete 38-byte supplier-shared copier, without electing a historical name or release. */
public class BorlandFarCopyAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland far copy (qualified 16-bit)";
    public static final String CONVENTION = "borland_far_copy_16far";
    private static final byte[] BODY = HexFormat.of().parseHex("45558bec56578cdac47e06c5760a8b4e0ed1e9fcf3a57301a48eda8b56088b46065f5e5d4dcb");
    private static final int[] INSTRUCTION_LENGTHS = { 1, 1, 2, 1, 1, 2, 3, 3, 3, 2, 1, 2, 2, 1, 2, 3, 3, 1, 1, 1, 1, 1 };
    private static final String COMMENT = "[Qualified Borland far copy]\n"
        + "Complete 38-byte body matches retained CWM 3.1 FMEMCPY/__fmemcpy and CWL 3.1/4.5 memcpy; neither historical spelling nor exclusive release is inferred.\n"
        + "No incoming GPR argument: destination offset/selector at entry SP+4/+6; source at SP+8/+10; unsigned WORD byte count at SP+12.\n"
        + "Plain RETF: zero argument purge, 4-byte far return, ten caller-owned argument bytes. FarAddress16 is an offset/selector record, not a flat pointer or selector mapping.\n"
        + "Returned DX:AX freshly rereads current destination selector then offset after copying; aliases may distinguish it from the initial LES destination.\n"
        + "With an intact frame and ordinary non-disruptive accesses, low 16-bit BP/SI/DI/DS restored, BX untouched, SS not written; AX/DX/CX/ES changed, CX=0, ES=initial destination selector, DF=0. Upper-register behavior is not generalized.\n"
        + "CF retains original count parity from SHR; final DEC BP sets the other arithmetic flags. Prototype clobbers do not compute these values.\n"
        + "Forward WORD copies then optional BYTE; not memmove. Prototype does not model exact memory effects, faults, frame aliases or source-domain C behavior.";

    public BorlandFarCopyAnalyzer() {
        super(NAME, "Recognize the complete evidenced far copier and apply its caller-owned frame and DX:AX record result.", "qualified_borland_far_copy", CONVENTION, "borland-far-copy.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        DataType addressType = BorlandDataTypes.farAddress16(program);
        // Multi-register storage is most-significant piece first: selector DX, offset AX.
        VariableStorage result = new VariableStorage(program, program.getRegister("DX"), program.getRegister("AX"));
        function.updateFunction(CONVENTION, new ReturnParameterImpl(addressType, result, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("destination", addressType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("source", addressType, 8, program, SourceType.ANALYSIS),
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, 12, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_far_copy", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland far copy]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
