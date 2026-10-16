package dev.sangoi.ghidra.legacy;

import java.util.Arrays;
import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** The complete move core, qualified together with its distinct far wrapper. */
public class BorlandFmovmemAnalyzer extends QualifiedRuntimeHelperAnalyzer {
    public static final String NAME = "Borland fmovmem (qualified 16-bit)";
    public static final String CONVENTION = "borland_fmovmem_16far";
    private static final byte[] BODY = HexFormat.of().parseHex("45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb");
    private static final int[] INSTRUCTION_LENGTHS = { 1, 1, 2, 1, 1, 1, 3, 3, 3, 3, 2, 2, 2, 2, 2, 1, 3, 2, 1, 2, 3, 3, 3, 2, 2, 2, 1, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 };
    static final byte[] WRAPPER_BODY = HexFormat.of().parseHex("45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb");
    static final int[] WRAPPER_INSTRUCTION_LENGTHS = { 1, 1, 2, 1, 1, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 1, 1, 1, 1, 1 };
    private static final String COMMENT = "[Qualified Borland fmovmem]\n"
        + "Complete 89-byte/49-instruction core and adjacent distinct 39-byte/20-instruction fmemmove wrapper equal all 128 CODE bytes of the retained genuine movmem.cas member. No historical spelling or exclusive compiler release is inferred.\n"
        + "Source offset/selector at entry SP+4/+6; destination at SP+8/+10; unsigned WORD byte count at SP+12. FarAddress16 is an offset/selector record, not a flat/host pointer or live selector mapping. No incoming GPR argument.\n"
        + "Plain RETF: four-byte far return, purge0, ten caller-owned argument bytes. Analysis return is void: no meaningful destination return is established.\n"
        + "Unsigned raw source selector versus destination selector, then offset comparison selects forward or backward direction. Backward setup adds count and decrements indices modulo 16 bits; odd-byte alignment, WORD copies and carry-tail handling retain direction-specific adjustments. Final CLD precedes register restoration and RETF. This is not unrestricted modern memmove or a linear-address overlap test.\n"
        + "With an ordinary intact frame and valid non-disruptive accesses, low16 BP/SI/DI/DS restored, SS not written; BX/AX/DX/CX/ES not preserved. Flags and DF are conservatively clobbered, not computed outcomes. Upper-register behavior is not generalized.\n"
        + "Whole-family bytes, every native instruction's 16-bit context and the actual wrapper PUSH CS/near CALL to this core are separately qualified before this contract. Prototype does not model memory effects, faults, arbitrary aliases, selector validity or source-domain C semantics.";

    public BorlandFmovmemAnalyzer() {
        super(NAME, "Recognize the complete qualified move family and its void source-first core.", "qualified_borland_fmovmem", CONVENTION, "borland-fmovmem.xml", BODY, INSTRUCTION_LENGTHS);
    }

    @Override
    protected void applyContract(Program program, Function function) throws Exception {
        requireQualifiedFamily(program, function.getEntryPoint());
        function.setBody(new AddressSet(function.getEntryPoint(), function.getEntryPoint().add(88)));
        var addressType = BorlandDataTypes.farAddress16(program);
        function.updateFunction(CONVENTION, new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, program), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
            new ParameterImpl("source", addressType, 4, program, SourceType.ANALYSIS),
            new ParameterImpl("destination", addressType, 8, program, SourceType.ANALYSIS),
            new ParameterImpl("byte_count", UnsignedShortDataType.dataType, 12, program, SourceType.ANALYSIS));
        function.setStackPurgeSize(0);
        if (function.getSymbol().getSource() == SourceType.DEFAULT) {
            function.setName("qualified_borland_fmovmem", SourceType.ANALYSIS);
        }
        String previous = function.getComment();
        if (previous == null || !previous.contains("[Qualified Borland fmovmem]")) {
            function.setComment(previous == null || previous.isBlank() ? COMMENT : previous + "\n\n" + COMMENT);
        }
    }

    static void requireQualifiedFamily(Program program, Address core) throws Exception {
        byte[] actual = new byte[BODY.length];
        if (program.getMemory().getBytes(core, actual) != BODY.length || !Arrays.equals(actual, BODY)) {
            throw new IllegalStateException("Move family lacks the complete qualified 89-byte core");
        }
        requireQualifiedWrapper(program, core.add(89));
        var disassembly = new DisassembleCommand(core, new AddressSet(core, core.add(88)), true);
        disassembly.enableCodeAnalysis(false);
        if (!disassembly.applyTo(program) || !hasQualifiedInstructions(program, core, INSTRUCTION_LENGTHS)) {
            throw new IllegalStateException("Move core has unqualified native instruction boundaries or 16-bit context");
        }
        var call = program.getListing().getInstructionAt(core.add(111));
        if (call == null || !call.getFlowType().isCall() || call.getFlows().length != 1 || !call.getFlows()[0].equals(core)) {
            throw new IllegalStateException("Move wrapper's native near CALL does not target its qualified core");
        }
    }

    private static void requireQualifiedWrapper(Program program, Address wrapper) throws Exception {
        byte[] actual = new byte[WRAPPER_BODY.length];
        if (program.getMemory().getBytes(wrapper, actual) != WRAPPER_BODY.length || !Arrays.equals(actual, WRAPPER_BODY)) {
            throw new IllegalStateException("Move family lacks the complete qualified 39-byte wrapper");
        }
        var disassembly = new DisassembleCommand(wrapper, new AddressSet(wrapper, wrapper.add(38)), true);
        disassembly.enableCodeAnalysis(false);
        if (!disassembly.applyTo(program) || !hasQualifiedInstructions(program, wrapper, WRAPPER_INSTRUCTION_LENGTHS)) {
            throw new IllegalStateException("Move wrapper has unqualified native instruction boundaries or 16-bit context");
        }
    }
}
