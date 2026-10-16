package dev.sangoi.ghidra.legacy;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** The complete destination-return wrapper, never qualified without its actual move core. */
public class BorlandFmemmoveAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland fmemmove (qualified 16-bit)";
    public static final String CONVENTION = "borland_fmemmove_16far";
    private static final String COMMENT = "[Qualified Borland fmemmove]\n"
        + "Complete 39-byte/20-instruction wrapper and its distinct preceding 89-byte/49-instruction fmovmem core equal the retained genuine 128-byte movmem.cas family. No exclusive release or historical declaration is inferred.\n"
        + "Destination offset/selector at entry SP+4/+6, source at SP+8/+10, unsigned WORD count at SP+12; no incoming GPR argument. FarAddress16 is an offset/selector record, not a flat/host pointer or live selector mapping.\n"
        + "Pushes five WORDs (count, destination selector/offset, source selector/offset), then PUSH CS and an actual near CALL to the separately qualified source-first core. Inner plain RETF removes the four-byte far-compatible return; ADD SP,0a removes the ten inner argument bytes. Outer plain RETF has purge0, far return4, ten caller-owned argument bytes.\n"
        + "After the core returns, freshly rereads current destination selector into DX then offset into AX before restoring the frame. Native custom return storage is DX:AX FarAddress16, not unconditional identity with initial LES destination or initial argument memory under aliases.\n"
        + "With ordinary intact frames and valid non-disruptive accesses, low16 BP/SI/DI/DS restored, SS not written; BX/AX/DX/CX/ES not preserved. Unlike the distinct forward-only 38-byte copier, BX is clobbered. Flags and DF are conservatively clobbered, not computed outcomes.\n"
        + "The core uses unsigned raw-selector/offset direction selection, modular backward setup, alignment and tail handling, and final CLD. Not unrestricted modern memmove, fault/alias safety, selector resolution or host pointer semantics. Prototype does not model exact memory effects or source-domain C behavior.";

    public BorlandFmemmoveAnalyzer() {
        super(NAME, "Recognize the whole qualified move family and its freshly reread DX:AX wrapper result.", "qualified_borland_fmemmove", CONVENTION, "borland-fmemmove.xml", BorlandFmovmemAnalyzer.WRAPPER_BODY, BorlandFmovmemAnalyzer.WRAPPER_INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        BorlandFmovmemAnalyzer.requireQualifiedFamily(program, function.getEntryPoint().subtract(89));
        function.setBody(new AddressSet(function.getEntryPoint(), function.getEntryPoint().add(38)));
        var addressType = BorlandDataTypes.farAddress16(program);
        var result = new VariableStorage(program, program.getRegister("DX"), program.getRegister("AX"));
        function.updateFunction(CONVENTION, new ReturnParameterImpl(addressType, result, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("destination", addressType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("source", addressType, 8, program, SourceType.ANALYSIS),
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, 12, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_fmemmove", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland fmemmove]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }
}
