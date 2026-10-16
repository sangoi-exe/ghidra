/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Test of DecompilerSwitchAnalyzer
 */
public class DecompilerSwitchAnalyzerTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;
	
	private DecompilerSwitchAnalyzer analyzer;

	public DecompilerSwitchAnalyzerTest() {
		super();
	}

	protected void setAnalysisOptions(String optionName) {
		int txId = program.startTransaction("Analyze");
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analysisOptions.setBoolean(optionName, false);
		program.endTransaction(txId, true);
	}
	
	@Test
	public void testDefaultSwitchLabelAndFlow() throws Exception {

		builder = new ProgramBuilder("SwitchDefaultTest", "x86:LE:64:default", "gcc", null);

		// 
		//		void main(undefined4 param_1)
		//
		//		{
		//		  switch(param_1) {
		//		  case 0:
		//		    puts("case 0");
		//		    break;
		//		  case 1:
		//		    puts("case 1");
		//		    break;
		//		  case 2:
		//		    puts("case 2");
		//		    break;
		//		  case 3:
		//		    puts("case 3");
		//		    break;
		//		  case 4:
		//		    puts("case 4");
		//		    break;
		//		  case 5:
		//		    puts("case 5");
		//		    break;
		//		  case 6:
		//		    puts("case 6");
		//		    break;
		//		  case 7:
		//		    puts("case 7");
		//		    break;
		//		  case 8:
		//		    puts("case 8");
		//		    break;
		//		  case 9:
		//		    puts("case 9");
		//		    break;
		//		  default:
		//		    puts("default");
		//		  }
		//		                    /* WARNING: Subroutine does not return */
		//		  exit(0);
		//		}
		
		builder.setBytes("0x101169",
			"f30f1efa554889" + 
			"e54883ec10897dfc488975f0837dfc09" + 
			"0f87d70000008b45fc488d1485000000" + 
			"00488d05bc0e00008b04024898488d15" + 
			"b00e00004801d03effe0488d05530e00" + 
			"004889c7e8a7feffffe9ae000000488d" + 
			"05460e00004889c7e893feffffe99a00" + 
			"0000488d05390e00004889c7e87ffeff" + 
			"ffe986000000488d052c0e00004889c7" + 
			"e86bfeffffeb75488d05220e00004889" + 
			"c7e85afeffffeb64488d05180e000048" + 
			"89c7e849feffffeb53488d050e0e0000" + 
			"4889c7e838feffffeb42488d05040e00" + 
			"004889c7e827feffffeb31488d05fa0d" + 
			"00004889c7e816feffffeb20488d05f0" + 
			"0d00004889c7e805feffffeb0f488d05" + 
			"e60d00004889c7e8f4fdffffbf000000" + 
			"00e8fafdffff");

		// switch table
		builder.setBytes("0x102054",
			"56f1ffff6af1ffff7ef1ffff" + 
			"92f1ffffa3f1ffffb4f1ffffc5f1ffff" + 
			"d6f1ffffe7f1fffff8f1ffff011b033b");

		builder.disassemble("0x101169", 64);
		
		builder.createFunction("0x101169");

		analyzer = new DecompilerSwitchAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x101169");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(0x200));
		analyze(addressSet);
		
		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(addr("0x0010125d"));
		assertEquals("Default label set", primarySymbol.getName(), "default");
		assertEquals("Switch space set", primarySymbol.getParentNamespace().getName(), "switchD_001011a7");
		
		primarySymbol = program.getSymbolTable().getPrimarySymbol(addr("0x0010124c"));
		assertEquals("Case label set", primarySymbol.getName(), "caseD_9");
		assertEquals("Switch space set", primarySymbol.getParentNamespace().getName(), "switchD_001011a7");

		Instruction instr = listing.getInstructionAt(addr("0x001011a7"));
		assertNoOperandReference(0, instr);
		assertNoOperandReference(1, instr);
		assertNumMnemonicReferences(instr, 10);
		assertMnemonicReferenceTo(instr, addr("0x001011aa"));
		assertMnemonicReferenceTo(instr, addr("0x001011be"));
		assertMnemonicReferenceTo(instr, addr("0x001011d2"));
		assertMnemonicReferenceTo(instr, addr("0x001011e6"));
		assertMnemonicReferenceTo(instr, addr("0x001011f7"));
		assertMnemonicReferenceTo(instr, addr("0x00101208"));
		assertMnemonicReferenceTo(instr, addr("0x00101219"));
		assertMnemonicReferenceTo(instr, addr("0x0010122a"));
		assertMnemonicReferenceTo(instr, addr("0x0010123b"));
		assertMnemonicReferenceTo(instr, addr("0x0010124c"));
		
	}
	
	private void assertNoOperandReference(int opIndex, Instruction instr) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("No reference on operand " + opIndex, 0, refs.length);
	}

	@Test
	public void testLoadTablePreservesArray() throws Exception {
		assertLoadTablePreservesData(new ArrayDataType(WordDataType.dataType, 24, 2),
			"0x1000");
	}

	@Test
	public void testLoadTablePreservesStructure() throws Exception {
		StructureDataType structure = new StructureDataType("ExistingTable", 0);
		structure.add(new ArrayDataType(WordDataType.dataType, 24, 2));
		assertLoadTablePreservesData(structure, "0x1000");
	}

	@Test
	public void testLoadTablePreservesArrayStartingBeforeTable() throws Exception {
		assertLoadTablePreservesData(new ArrayDataType(WordDataType.dataType, 24, 2),
			"0x0fff");
	}

	@Test
	public void testLoadTablePreservesArrayStartingInsideCell() throws Exception {
		assertLoadTablePreservesData(new ArrayDataType(WordDataType.dataType, 24, 2),
			"0x1001");
	}

	private void assertLoadTablePreservesData(DataType dataType, String dataAddress) throws Exception {
		createLoadTableProgram();
		int txId = program.startTransaction("Test load table preservation");
		try {
			Listing listing = program.getListing();
			Address start = addr(dataAddress);
			Data existing = listing.createData(start, dataType);
			Address end = existing.getMaxAddress();
			ReferenceManager references = program.getReferenceManager();
			Reference first = references.addMemoryReference(start, addr("0x1100"), RefType.DATA,
				SourceType.USER_DEFINED, 0);
			Reference last = references.addMemoryReference(end, addr("0x1102"), RefType.DATA,
				SourceType.USER_DEFINED, 0);
			Symbol label = program.getSymbolTable().createLabel(start, "existing_table",
				SourceType.USER_DEFINED);

			labelLoadTable();

			Data preserved = listing.getDefinedDataAt(start);
			assertNotNull("Existing data was cleared", preserved);
			assertTrue(dataType.isEquivalent(preserved.getDataType()));
			assertEquals(end, preserved.getMaxAddress());
			assertArrayEquals(new Reference[] { first }, references.getReferencesFrom(start));
			assertArrayEquals(new Reference[] { last }, references.getReferencesFrom(end));
			assertEquals(label, program.getSymbolTable().getPrimarySymbol(start));
		}
		finally {
			program.endTransaction(txId, true);
			builder.dispose();
		}
	}

	@Test
	public void testLoadTableCreatesCellsInUndefinedStorage() throws Exception {
		createLoadTableProgram();
		int txId = program.startTransaction("Test undefined load table");
		try {
			// Include explicitly defined undefined storage as well as untyped bytes.
			program.getListing().createData(addr("0x1000"), Undefined8DataType.dataType);
			labelLoadTable();
			assertLoadTableCells();
		}
		finally {
			program.endTransaction(txId, true);
			builder.dispose();
		}
	}

	@Test
	public void testLoadTablePreservesExistingCells() throws Exception {
		createLoadTableProgram();
		int txId = program.startTransaction("Test existing load table cells");
		try {
			for (int i = 0; i < 24; i++) {
				program.getListing().createData(addr("0x1000").add(2 * i), WordDataType.dataType);
			}
			ReferenceManager references = program.getReferenceManager();
			Reference first = references.addMemoryReference(addr("0x1000"), addr("0x1100"),
				RefType.DATA, SourceType.USER_DEFINED, 0);
			Reference last = references.addMemoryReference(addr("0x102e"), addr("0x1102"),
				RefType.DATA, SourceType.USER_DEFINED, 0);

			labelLoadTable();

			assertLoadTableCells();
			assertArrayEquals(new Reference[] { first }, references.getReferencesFrom(addr("0x1000")));
			assertArrayEquals(new Reference[] { last }, references.getReferencesFrom(addr("0x102e")));
		}
		finally {
			program.endTransaction(txId, true);
			builder.dispose();
		}
	}

	private void createLoadTableProgram() throws Exception {
		builder = new ProgramBuilder("LoadTableTest", "x86:LE:32:default", "gcc", null);
		builder.createMemory("tables", "0x0f00", 0x300);
		program = builder.getProgram();
	}

	private void labelLoadTable() throws Exception {
		JumpTable table = new JumpTable();
		JumpTable.LoadTable loadTable = (JumpTable.LoadTable) invokeConstructor(
			JumpTable.LoadTable.class, new Class<?>[] { JumpTable.class }, new Object[] { table });
		setInstanceField("addr", loadTable, addr("0x1000"));
		setInstanceField("size", loadTable, 2);
		setInstanceField("num", loadTable, 24);
		DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(null);
		setInstanceField("program", cmd, program);
		invokeInstanceMethod("labelLoadTable", cmd,
			new Class<?>[] { JumpTable.LoadTable.class, Address[].class, Symbol[].class,
				Namespace.class, TaskMonitor.class },
			new Object[] { loadTable, new Address[] { addr("0x1100") }, new Symbol[0],
				program.getGlobalNamespace(), TaskMonitor.DUMMY });
	}

	private void assertLoadTableCells() {
		for (int i = 0; i < 24; i++) {
			Data cell = program.getListing().getDefinedDataAt(addr("0x1000").add(2 * i));
			assertNotNull("Missing load table cell " + i, cell);
			assertEquals(2, cell.getLength());
			assertTrue(cell.getDataType() instanceof AbstractIntegerDataType);
		}
	}
	
	private void assertNumOperandReferences(int opIndex, Instruction instr, int num) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("Operand " + opIndex + " num refs", num, refs.length);
	}
	
	private void assertNumMnemonicReferences(Instruction instr, int num) {
		Reference[] refs = instr.getMnemonicReferences();
		assertEquals("Mnemonic num refs", num, refs.length);
	}

	private void assertMnemonicReferenceTo(Instruction instr, Address to) {
		Reference[] refs = instr.getMnemonicReferences();
		boolean found = false;
		for (Reference reference : refs) {
			if (reference.getToAddress().equals(to)) {
				found = true;
				break;
			}
		}
		assertTrue("Missing Mnemonic Reference " + to + " on " + instr, found);
	}
	
	private void assertOperandReferenceTo(int opIndex, Instruction instr, Address to) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		boolean found = false;
		for (Reference reference : refs) {
			if (reference.getToAddress().equals(to)) {
				found = true;
				break;
			}
		}
		assertTrue("Missing Reference " + to + " on " + instr, found);
	}

	private void analyze(AddressSet addrs) throws Exception {
		analyzer.added(program, addrs, TaskMonitor.DUMMY, null);
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
