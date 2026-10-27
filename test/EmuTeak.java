// P-code semantics check for the Teak module: runs hand-computed cases from test/emu/cases.txt in Ghidra's emulator
// (EmulatorHelper) and compares registers, flags, data/program memory and the program counter.
//
// Case format ('#' comments):
//   defaults <reg> <value> ...         registers set at the start of every case (SATA, CMD, CPC, CCNTA, CREP = 1 ...)
//   case <name> [modulo] [broken]      "modulo" cases run in the modulo language, "broken" ones carry a deliberately wrong expectation
//   code[@<word-address>] <hex words>  CODE words (default address 0x1000, the entry point)
//   asm <text> ; <text> ...            what the instructions starting at the entry point must disassemble to
//   steps <n>                          number of instructions to execute (default: until the pc reaches the end of the first code block)
//   set <reg> <value> | set mem:<addr> <value> | set pmem:<addr> <value>
//   expect <reg> <value> | expect mem:<addr> <value> | expect pc <value>
//   end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class EmuTeak extends GhidraScript {
	private static class Case {
		String name;
		boolean modulo, broken;
		Map<Long, int[]> code = new LinkedHashMap<>();
		String[] asm;
		int steps = -1;
		Map<String, BigInteger> set = new LinkedHashMap<>();
		Map<String, BigInteger> expect = new LinkedHashMap<>();
	}

	private final Map<String, BigInteger> defaults = new LinkedHashMap<>();

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0 && !line.startsWith("asm ")) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				if (f[0].startsWith("code")) {
					long addr = f[0].contains("@") ? Long.parseLong(f[0].substring(5), 16) : 0x1000;
					int[] w = new int[f.length - 1];
					for (int i = 1; i < f.length; i++) {
						w[i - 1] = Integer.parseInt(f[i], 16);
					}
					c.code.put(addr, w);
					continue;
				}
				switch (f[0]) {
					case "defaults":
						for (int i = 1; i + 1 < f.length; i += 2) {
							defaults.put(f[i], new BigInteger(f[i + 1], 16));
						}
						break;
					case "case":
						c = new Case();
						c.name = f[1];
						for (int i = 2; i < f.length; i++) {
							c.modulo |= f[i].equals("modulo");
							c.broken |= f[i].equals("broken");
						}
						break;
					case "asm":
						c.asm = line.substring(3).trim().split("\\s*;\\s*");
						break;
					case "steps":
						c.steps = Integer.parseInt(f[1]);
						break;
					case "set":
						c.set.put(f[1], new BigInteger(f[2], 16));
						break;
					case "expect":
						c.expect.put(f[1], new BigInteger(f[2], 16));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private static String norm(String s) {
		return s.replace(" ", "").toLowerCase().replaceAll("0x0+([0-9a-f])", "0x$1");
	}

	private String dis(Address a, int[] w, int idx) {
		ghidra.program.model.lang.Language lang = currentProgram.getLanguage();
		byte[] b = new byte[16];
		for (int i = 0; i < 4 && idx + i < w.length; i++) {
			b[2 * i] = (byte) w[idx + i];
			b[2 * i + 1] = (byte) (w[idx + i] >> 8);
		}
		try {
			ghidra.program.model.lang.ProcessorContextImpl ctx = new ghidra.program.model.lang.ProcessorContextImpl(lang);
			ghidra.program.model.lang.Register cr = lang.getContextBaseRegister();
			if (cr != null) {
				ctx.setRegisterValue(currentProgram.getProgramContext().getDefaultDisassemblyContext());
			}
			ghidra.program.model.mem.MemBuffer buf = new ghidra.program.model.mem.ByteMemBufferImpl(a, b, true);
			ghidra.program.model.lang.InstructionPrototype proto = lang.parse(buf, ctx, false);
			ghidra.app.util.PseudoInstruction pi = new ghidra.app.util.PseudoInstruction(currentProgram, a, proto, buf, ctx);
			return pi.toString() + "|" + pi.getLength() / 2;
		}
		catch (Exception e) {
			return "BAD|1";
		}
	}

	private String runCase(Case c) throws Exception {
		AddressSpace code = currentProgram.getAddressFactory().getAddressSpace("CODE");
		AddressSpace data = currentProgram.getAddressFactory().getAddressSpace("DATA");
		int[] main = c.code.get(0x1000L);
		if (c.asm != null) {
			int idx = 0;
			for (int i = 0; i < c.asm.length; i++) {
				String[] d = dis(code.getAddress(2 * (0x1000 + idx)), main, idx).split("\\|");
				if (!norm(d[0]).equals(norm(c.asm[i]))) {
					return String.format("instruction %d disassembles as '%s', not '%s'", i, d[0], c.asm[i]);
				}
				idx += Integer.parseInt(d[1]);
			}
			if (idx != main.length) {
				return "asm does not cover the code block";
			}
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (Map.Entry<Long, int[]> e : c.code.entrySet()) {
				byte[] b = new byte[2 * e.getValue().length + 8];
				for (int i = 0; i < e.getValue().length; i++) {
					b[2 * i] = (byte) e.getValue()[i];
					b[2 * i + 1] = (byte) (e.getValue()[i] >> 8);
				}
				emu.writeMemory(code.getAddress(2 * e.getKey()), b);
			}
			for (Map.Entry<String, BigInteger> e : defaults.entrySet()) {
				emu.writeRegister(e.getKey(), e.getValue());
			}
			for (Map.Entry<String, BigInteger> e : c.set.entrySet()) {
				String k = e.getKey();
				long v = e.getValue().longValue();
				if (k.startsWith("mem:")) {
					emu.writeMemory(data.getAddress(2 * Long.parseLong(k.substring(4), 16)), new byte[] { (byte) v, (byte) (v >> 8) });
				}
				else if (k.startsWith("pmem:")) {
					emu.writeMemory(code.getAddress(2 * Long.parseLong(k.substring(5), 16)), new byte[] { (byte) v, (byte) (v >> 8) });
				}
				else {
					emu.writeRegister(k, e.getValue());
				}
			}
			emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(0x1000));
			long end = 0x1000 + main.length;
			int steps = 0;
			while (c.steps >= 0 ? steps < c.steps : emu.readRegister("pc").longValue() != end) {
				if (++steps > 2000) {
					return "did not reach the end (pc " + emu.readRegister("pc") + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at pc " + emu.readRegister("pc") + ": " + emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, BigInteger> e : c.expect.entrySet()) {
				String k = e.getKey();
				BigInteger got;
				if (k.startsWith("mem:")) {
					byte[] b = emu.readMemory(data.getAddress(2 * Long.parseLong(k.substring(4), 16)), 2);
					got = BigInteger.valueOf((b[0] & 0xff) | ((b[1] & 0xff) << 8));
				}
				else if (k.startsWith("pmem:")) {
					byte[] b = emu.readMemory(code.getAddress(2 * Long.parseLong(k.substring(5), 16)), 2);
					got = BigInteger.valueOf((b[0] & 0xff) | ((b[1] & 0xff) << 8));
				}
				else {
					got = emu.readRegister(k);
				}
				if (!got.equals(e.getValue())) {
					bad.append(String.format(" %s=0x%s (expected 0x%s)", k, got.toString(16), e.getValue().toString(16)));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		String lang = currentProgram.getLanguageID().getIdAsString();
		boolean modulo = lang.endsWith("modulo");
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			if (c.modulo != modulo) {
				continue;
			}
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, broken expectation %s%n", lang, pass, fail + brokenMissed,
			brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
