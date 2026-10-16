package dev.sangoi.ghidra.legacy;

import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;

/** The complete internal body corresponding to the supplied CWM 3.1 MEMSET member. */
public class BorlandSetmemAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland setmem (qualified 16-bit)";
    public static final String CONVENTION = "borland_setmem_16far";
    private static final byte[] BODY = HexFormat.of().parseHex("45558bec571e078b7e068b4e088a460a8ae0fcf7c701007404e309aa49d1e9f3ab7301aa5f5d4dcb");
    private static final int[] INSTRUCTION_LENGTHS = { 1, 1, 2, 1, 1, 1, 3, 3, 3, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1 };
    private static final String COMMENT = "[Qualified Borland setmem]\n"
        + "Complete 40-byte internal body corresponds to _setmem at CWM 3.1 MEMSET _TEXT:0000; the adjacent 29-byte wrapper corresponds to _memset at 0028. No exclusive compiler release or historical C declaration is inferred.\n"
        + "Analysis inputs are WORDs: DS-selected destination offset at entry SP+4, unsigned byte count at SP+6, fill word at SP+8 (only its low byte is read). No incoming GPR argument or flat/host pointer.\n"
        + "Plain RETF: zero argument purge, four-byte far return, six caller-owned argument bytes.\n"
        + "On ordinary completion with intact frame and non-disruptive accesses, ES=DS, AX=fill_low_byte*0101h, CX=0, DF=0; BP/DI restored, BX/DX/SI/DS untouched, SS not written. Low-16-bit claims do not generalize upper registers or arbitrary frame/destination aliases.\n"
        + "Forward fill: odd destination first consumes one byte unless count is zero; remaining WORDs use REP STOSW, then optional carry-tail STOSB. Final DEC BP sets arithmetic flags except CF; CF comes from SHR count, or TEST-cleared zero on the odd-destination zero-count path. Flags are not preserved.\n"
        + "The AX WORD result records actual duplicated-byte register output, not a historical scalar return declaration. Prototype clobbers do not compute AX/CX/ES/DF/flags or fill memory effects; selector validity, faults, frame aliases and source-domain C semantics remain unresolved.";

    public BorlandSetmemAnalyzer() {
        super(NAME, "Recognize the complete evidenced internal fill body and its caller-owned WORD frame.", "qualified_borland_setmem", CONVENTION, "borland-setmem.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        function.updateFunction(CONVENTION, new ReturnParameterImpl(UnsignedShortDataType.dataType, program.getRegister("AX"), program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("destination_offset", UnsignedShortDataType.dataType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, 6, program, SourceType.ANALYSIS),
            new ParameterImpl("fill_word_low_byte", UnsignedShortDataType.dataType, 8, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_setmem", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland setmem]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }

    static void requireQualifiedTarget(Program program, Address target) throws Exception {
        // The wrapper's transitive register contract requires this actual callee, not just E8C4FF.
        byte[] actual = new byte[BODY.length];
        if (program.getMemory().getBytes(target, actual) != BODY.length || !java.util.Arrays.equals(actual, BODY)) {
            throw new IllegalStateException("Wrapper's literal internal target is not the qualified 40-byte fill body");
        }
        var body = new AddressSet(target, target.add(39));
        var disassembly = new DisassembleCommand(target, body, true);
        disassembly.enableCodeAnalysis(false);
        if (!disassembly.applyTo(program)) {
            throw new IllegalStateException("Wrapper's internal target does not disassemble natively");
        }
        if (!hasQualifiedInstructions(program, target, INSTRUCTION_LENGTHS)) {
            throw new IllegalStateException("Wrapper's internal target has unqualified instruction boundaries or 16-bit context");
        }
    }
}
