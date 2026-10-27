// Decode a list of byte strings (one hex string per line of the input file) with the program's
// language, each placed at a fixed address, and print "<hex> <len> <text>" per case ("BAD" if the
// language rejects it). Branch targets are relative to the address 0x1000.
// Script args: <cases.txt> <outfile> [ctxfield=value ...]
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class DisCases extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		long base = 0x1000;
		for (int i = 2; i < args.length; i++) {
			if (args[i].startsWith("@")) {
				base = Long.parseLong(args[i].substring(1), 16);
			}
		}
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				byte[] b = new byte[line.length() / 2 + 8];
				for (int i = 0; i < line.length() / 2; i++) {
					b[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
				}
				ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
				Register cr = lang.getContextBaseRegister();
				if (cr != null && cr != Register.NO_CONTEXT) {
					ctx.setRegisterValue(
						currentProgram.getProgramContext().getDefaultDisassemblyContext());
				}
				for (int i = 2; i < args.length; i++) {
					if (args[i].startsWith("@")) {
						continue;
					}
					String[] kv = args[i].split("=");
					ctx.setValue(lang.getRegister(kv[0]), new BigInteger(kv[1]));
				}
				String text;
				int n;
				try {
					MemBuffer buf = new ByteMemBufferImpl(a, b, true);
					InstructionPrototype proto = lang.parse(buf, ctx, false);
					PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
					text = pi.toString();
					n = pi.getLength();
				}
				catch (Exception e) {
					text = "BAD"; if (System.getenv("PDK_DEBUG") != null) { println("BAD " + line + ": " + e); }
					n = 0;
				}
				out.printf("%s %d %s%n", line, n, text);
			}
		}
		out.close();
	}
}
