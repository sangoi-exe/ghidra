package dev.sangoi.ghidra.legacy;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;

/** Mechanical storage records shared by qualified Borland helper contracts. */
public final class BorlandDataTypes {
    private BorlandDataTypes() {
    }

    public static DataType farAddress16(Program program) {
        var manager = program.getDataTypeManager();
        StructureDataType farAddress = new StructureDataType(new CategoryPath("/LegacyToolchains/Borland"), "FarAddress16", 0, manager);
        farAddress.add(UnsignedShortDataType.dataType, "offset", "16-bit offset");
        farAddress.add(UnsignedShortDataType.dataType, "selector", "16-bit selector/segment word; address mapping is not inferred");
        return manager.resolve(farAddress, DataTypeConflictHandler.DEFAULT_HANDLER);
    }
}
