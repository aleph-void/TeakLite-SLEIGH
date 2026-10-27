// Differential single-step runner: executes one instruction from a given state in Ghidra's emulator and prints the state.
// Input (script arg 0): lines "<opcode hex> <expansion hex> name=hex ..." with names of the module's registers
//   (pc is a word address in CODE; "mem<addr>=value" lines are not accepted: the data window is filled with the
//   same pattern as test/teakra-step).  Script arg 1: output file; arg 2: file with the register names to print.
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class TeakStep extends GhidraScript {
	static final int WLO = 0, WHI = 0x3000;

	static int memf(int a) {
		int h = a * 40503;
		return ((h ^ (h >>> 7) ^ ((a >>> 3) * 7919)) ^ 0x5a5a) & 0xFFFF;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<String> watch = new ArrayList<>();
		try (BufferedReader r = new BufferedReader(new FileReader(args[2]))) {
			String l;
			while ((l = r.readLine()) != null) {
				if (!l.isBlank()) {
					watch.add(l.trim());
				}
			}
		}
		List<String> zero = new ArrayList<>();
		if (args.length > 3) {
			try (BufferedReader r = new BufferedReader(new FileReader(args[3]))) {
				String l;
				while ((l = r.readLine()) != null) {
					if (!l.isBlank()) {
						zero.add(l.trim());
					}
				}
			}
		}
		AddressSpace code = currentProgram.getAddressFactory().getAddressSpace("CODE");
		AddressSpace data = currentProgram.getAddressFactory().getAddressSpace("DATA");
		byte[] init = new byte[(WHI - WLO) * 2];
		for (int a = WLO; a < WHI; a++) {
			int v = memf(a);
			init[2 * (a - WLO)] = (byte) v;
			init[2 * (a - WLO) + 1] = (byte) (v >> 8);
		}
		byte[] pinit = new byte[0x3000 * 2];
		for (int a = 0; a < 0x3000; a++) {
			int v = memf(a + 0x10000);
			pinit[2 * a] = (byte) v;
			pinit[2 * a + 1] = (byte) (v >> 8);
		}
		PrintStream out = new PrintStream(args[1]);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			long lastPc = -1;
			try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
				String line;
				while ((line = r.readLine()) != null) {
					String[] f = line.trim().split("\\s+");
					if (f.length < 2) {
						continue;
					}
					int op = Integer.parseInt(f[0], 16), ex = Integer.parseInt(f[1], 16);
					emu.writeMemory(data.getAddress(2 * WLO), init.clone());
					emu.writeMemory(code.getAddress(0), pinit.clone());
					// clear all registers first
					for (String w : watch) {
						emu.writeRegister(w, BigInteger.ZERO);
					}
					for (String w : zero) {
						emu.writeRegister(w, BigInteger.ZERO);
					}
					long pc = 0x1000;
					for (int i = 2; i < f.length; i++) {
						String[] kv = f[i].split("=");
						if (kv[0].equals("pc")) {
							pc = Long.parseLong(kv[1], 16);
						}
						else {
							emu.writeRegister(kv[0], new BigInteger(kv[1], 16));
						}
					}
					if (lastPc >= 0) {
						emu.writeMemory(code.getAddress(2 * lastPc), new byte[8]);
					}
					lastPc = pc;
					byte[] ib = { (byte) op, (byte) (op >> 8), (byte) ex, (byte) (ex >> 8), 0, 0, 0, 0 };
					emu.writeMemory(code.getAddress(2 * pc), ib);
					emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(pc));
					boolean ok;
					String err = "";
					try {
						ok = emu.step(monitor);
						if (!ok) {
							err = " ERR=" + String.valueOf(emu.getLastError()).replace(' ', '_');
						}
					}
					catch (Exception e) {
						ok = false;
						err = " ERR=" + e.toString().replace(' ', '_');
					}
					StringBuilder sb = new StringBuilder();
					sb.append(String.format("%04x %04x", op, ex)).append(err);
					for (String w : watch) {
						sb.append(' ').append(w).append('=').append(emu.readRegister(w).toString(16));
					}
					byte[] after = emu.readMemory(data.getAddress(2 * WLO), (WHI - WLO) * 2);
					for (int i = 0; i < after.length; i += 2) {
						if (after[i] != init[i] || after[i + 1] != init[i + 1]) {
							sb.append(String.format(" mem%x=%x", WLO + i / 2,
								(after[i] & 0xff) | ((after[i + 1] & 0xff) << 8)));
						}
					}
					byte[] pafter = emu.readMemory(code.getAddress(0), 0x3000 * 2);
					for (int i = 0; i < pafter.length; i += 2) {
						if (pafter[i] != pinit[i] || pafter[i + 1] != pinit[i + 1]) {
							sb.append(String.format(" pmem%x=%x", i / 2, (pafter[i] & 0xff) | ((pafter[i + 1] & 0xff) << 8)));
						}
					}
					out.println(sb);
				}
			}
		}
		finally {
			emu.dispose();
			out.close();
		}
	}
}
