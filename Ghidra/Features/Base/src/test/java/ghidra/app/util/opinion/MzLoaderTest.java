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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.ne.NewExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;

public class MzLoaderTest extends AbstractGenericTest {

	@Test
	public void testOldMzWithUnrecognizedNewHeader() throws IOException {
		// Reproduce the BCC 2.0 case: e_lfanew points inside DOS program data, not PE/NE.
		ByteBuffer bytes = createDosImage(0x10200, 0x10000);
		bytes.putInt(0x10000, 0x73635f20);
		try (ByteArrayProvider provider = new ByteArrayProvider(bytes.array())) {
			assertNull(new PortableExecutable(provider, SectionLayout.FILE, false, false)
					.getNTHeader());
			assertNull(new NewExecutable(provider, null).getWindowsHeader());
			assertFalse(new MzLoader().findSupportedLoadSpecs(provider).isEmpty());
		}
	}

	@Test
	public void testPeIsExcluded() throws IOException {
		ByteBuffer bytes = createDosImage(0x400, 0x80);
		bytes.putInt(0x80, 0x00004550); // PE signature
		bytes.putShort(0x84, (short) 0x14c); // x86
		bytes.putShort(0x86, (short) 1); // section count
		bytes.putShort(0x94, (short) 0xe0); // optional header size
		bytes.putShort(0x96, (short) 0x102); // executable, 32-bit
		bytes.putShort(0x98, (short) 0x10b); // PE32
		bytes.putInt(0xa8, 0x1000); // entry point
		bytes.putInt(0xac, 0x1000); // base of code
		bytes.putInt(0xb4, 0x400000); // image base
		bytes.putInt(0xb8, 0x1000); // section alignment
		bytes.putInt(0xbc, 0x200); // file alignment
		bytes.putInt(0xd0, 0x2000); // image size
		bytes.putInt(0xd4, 0x200); // header size
		bytes.putShort(0xdc, (short) 3); // console subsystem
		bytes.putInt(0xf4, 16); // data directory count
		bytes.position(0x178);
		bytes.put(new byte[] { '.', 't', 'e', 'x', 't', 0, 0, 0 });
		bytes.putInt(0x180, 1); // virtual size
		bytes.putInt(0x184, 0x1000); // virtual address
		bytes.putInt(0x188, 0x200); // raw size
		bytes.putInt(0x18c, 0x200); // raw offset
		bytes.putInt(0x19c, 0x60000020); // executable, readable code
		bytes.put(0x200, (byte) 0xc3);
		try (ByteArrayProvider provider = new ByteArrayProvider(bytes.array())) {
			assertNotNull(new PortableExecutable(provider, SectionLayout.FILE, false, false)
					.getNTHeader());
			assertTrue(new MzLoader().findSupportedLoadSpecs(provider).isEmpty());
		}
	}

	@Test
	public void testNeIsExcluded() throws IOException {
		ByteBuffer bytes = createDosImage(0x200, 0x80);
		bytes.putShort(0x80, (short) 0x454e); // NE signature
		bytes.putShort(0x84, (short) 0x40); // empty entry table
		bytes.putShort(0xa2, (short) 0x40); // empty segment table
		bytes.putShort(0xa4, (short) 0x40); // no resources
		bytes.putShort(0xa6, (short) 0x40); // empty resident name table
		bytes.putShort(0xa8, (short) 0x40); // empty module reference table
		bytes.putShort(0xaa, (short) 0x40); // empty imported name table
		bytes.putInt(0xac, 0xc0); // empty non-resident name table
		bytes.putShort(0xb2, (short) 4); // segment alignment shift
		bytes.put(0xb6, (byte) 2); // Windows
		try (ByteArrayProvider provider = new ByteArrayProvider(bytes.array())) {
			assertNull(new PortableExecutable(provider, SectionLayout.FILE, false, false)
					.getNTHeader());
			assertNotNull(new NewExecutable(provider, null).getWindowsHeader());
			assertTrue(new MzLoader().findSupportedLoadSpecs(provider).isEmpty());
		}
	}

	@Test
	public void testTruncatedDosHeaderReportsIoError() throws IOException {
		try (ByteArrayProvider provider = new ByteArrayProvider(new byte[] { 'M', 'Z', 0, 0 })) {
			assertThrows(IOException.class, () -> new MzLoader().findSupportedLoadSpecs(provider));
		}
	}

	private ByteBuffer createDosImage(int length, int newHeaderOffset) {
		ByteBuffer bytes = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
		bytes.putShort(0, (short) 0x5a4d);
		bytes.putShort(2, (short) (length % 512));
		bytes.putShort(4, (short) ((length + 511) / 512));
		bytes.putShort(8, (short) 4); // DOS header paragraphs
		bytes.putShort(0x18, (short) 0x1c); // empty relocation table
		bytes.putInt(0x3c, newHeaderOffset);
		return bytes;
	}
}
