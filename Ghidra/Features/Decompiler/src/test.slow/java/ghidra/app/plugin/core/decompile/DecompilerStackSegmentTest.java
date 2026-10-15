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

import ghidra.app.decompiler.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class DecompilerStackSegmentTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testSharedCompilerStackSegmentEncoding() throws Exception {
		for (String languageID : new String[] { "x86:LE:16:Protected Mode", "x86:LE:16:Real Mode",
			"x86:LE:32:System Management Mode" }) {
			Language language = DefaultLanguageService.getLanguageService()
					.getLanguage(new LanguageID(languageID));
			BasicCompilerSpec spec = (BasicCompilerSpec) language.getDefaultCompilerSpec();
			BasicCompilerSpec copy = new BasicCompilerSpec(spec);
			assertTrue(languageID, spec.isEquivalent(copy));
			XmlEncode encoder = new XmlEncode(false);
			copy.encode(encoder);
			assertTrue(languageID, encoder.toString().contains("segmentregister=\"SS\""));
			ProgramBuilder builder = new ProgramBuilder("StackSegment", language);
			DecompInterface decompiler = new DecompInterface();
			try {
				boolean opened = decompiler.openProgram(builder.getProgram());
				assertTrue(languageID + ": " + decompiler.getLastMessage(), opened);
			}
			finally {
				decompiler.dispose();
				builder.dispose();
			}
		}
	}

	@Test
	public void testCallReturnStackArgumentUsesDeclaredSelector() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("SegmentedCallReturn", "x86:LE:16:Protected Mode", "default", null);
		DecompInterface decompiler = new DecompInterface();
		try {
			// Observed regression input: JMP rel16 has no stack write at the call point.
			builder.setBytes("1000:1000", "e9 0d 00", true);
			builder.setBytes("1000:1010", "55 8b ec 8b 46 06 5d cb", true);
			Program program = builder.getProgram();
			assertTrue(program.getCompilerSpec() instanceof ProgramCompilerSpec);
			Function target = builder.createEmptyFunction("jump_target", null, "__cdecl16far",
				"1000:1010", 8, UnsignedShortDataType.dataType, UnsignedShortDataType.dataType);
			Function caller = builder.createEmptyFunction("jump_thunk", null, "__cdecl16far",
				"1000:1000", 3, UnsignedShortDataType.dataType, UnsignedShortDataType.dataType);
			assertEquals(4, target.getParameter(0).getStackOffset());
			assertTrue(decompiler.openProgram(program));
			assertTrue(decompiler.decompileFunction(caller, 30, TaskMonitor.DUMMY)
					.decompileCompleted());
			builder.tx(() -> program.getListing().getInstructionAt(caller.getEntryPoint())
					.setFlowOverride(FlowOverride.CALL_RETURN));
			decompiler.flushCache();
			DecompileResults result = decompiler.decompileFunction(caller, 30, TaskMonitor.DUMMY);
			assertTrue(result.getErrorMessage(), result.decompileCompleted());
			String text = result.getDecompiledFunction().getC();
			assertTrue(text, text.matches("(?s).*jump_target\\(\\*\\([^)]*\\*\\)segmentop\\(unaff_SS,.*"));
		}
		finally {
			decompiler.dispose();
			builder.dispose();
		}
	}
}
