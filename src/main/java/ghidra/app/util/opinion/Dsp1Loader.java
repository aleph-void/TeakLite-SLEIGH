/* ###
 * IP: Ghidra-Rare TeakLite module
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

/**
 * Loader for the "DSP1" firmware container of the Nintendo DSi / 3DS DSP (Teak): a 0x100 byte signature, the
 * magic "DSP1", a header with up to 10 segments and the segments themselves.  Program segments (memory type 0
 * or 1) become blocks of the CODE space, data segments (type 2) blocks of the DATA space; the start of every
 * program segment is an entry point (segment 0 is the reset / interrupt vector table at word address 0).
 * Layout as read by Teakra's dsp1_reader (MIT).
 */
public class Dsp1Loader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Nintendo DSP1 firmware (Teak)";
	private static final String LANGUAGE = "teak:LE:16:default";
	private static final int MAGIC_OFFSET = 0x100;
	private static final int HEADER_SIZE = 0x300;
	private static final int SEGMENTS_OFFSET = 0x120;
	private static final int SEGMENT_SIZE = 0x30;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < HEADER_SIZE) {
			return specs;
		}
		byte[] magic = provider.readBytes(MAGIC_OFFSET, 4);
		if (magic[0] == 'D' && magic[1] == 'S' && magic[2] == 'P' && magic[3] == '1') {
			specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE, "default"), true));
		}
		return specs;
	}

	private static long u32(byte[] b, int o) {
		return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8) | ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		byte[] header = provider.readBytes(0, HEADER_SIZE);
		int count = header[0x10e] & 0xff;     // num_segments
		AddressSpace code = program.getAddressFactory().getAddressSpace("CODE");
		AddressSpace data = program.getAddressFactory().getAddressSpace("DATA");
		try {
			for (int i = 0; i < count && i < 10; i++) {
				int o = SEGMENTS_OFFSET + i * SEGMENT_SIZE;
				long offset = u32(header, o);
				long address = u32(header, o + 4);    // word address
				long size = u32(header, o + 8);       // bytes
				int type = header[o + 15] & 0xff;
				if (size == 0 || offset + size > provider.length()) {
					continue;
				}
				byte[] bytes = provider.readBytes(offset, size);
				boolean isData = type == 2;
				AddressSpace space = isData ? data : code;
				Address start = space.getAddress(address * 2);
				String name = (isData ? "DATA" : "CODE") + "_" + i;
				MemoryBlock block = program.getMemory().createInitializedBlock(name, start,
					new ByteArrayInputStream(bytes), size, settings.monitor(), false);
				block.setRead(true);
				block.setWrite(isData);
				block.setExecute(!isData);
				if (!isData) {
					String label = address == 0 ? "_start" : "seg_" + Long.toHexString(address);
					program.getSymbolTable().createLabel(start, label, SourceType.IMPORTED);
					program.getSymbolTable().addExternalEntryPoint(start);
				}
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException("cannot load DSP1 image: " + e.getMessage(), e);
		}
	}
}
