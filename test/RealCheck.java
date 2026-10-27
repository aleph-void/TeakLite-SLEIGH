// After auto-analysis: dumps the listing (word address, words, text) to <out>.lst and prints instruction / function /
// bookmark counts and decompiler failures.  Script args: <outprefix>
//@category Testing

import java.io.PrintStream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Bookmark;
import java.util.Iterator;

public class RealCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String prefix = getScriptArgs()[0];
		PrintStream lst = new PrintStream(prefix + ".lst");
		int n = 0;
		for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
			StringBuilder w = new StringBuilder();
			for (byte b : ins.getBytes()) {
				w.append(String.format("%02x", b));
			}
			lst.printf("%x %s %s%n", ins.getAddress().getOffset() / 2, w, ins);
			n++;
		}
		lst.close();
		int bad = 0, err = 0;
		Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (it.hasNext()) {
			Bookmark b = it.next();
			if (b.getCategory().equals("Bad Instruction")) {
				bad++;
				println("bad instruction at " + b.getAddress() + ": " + b.getComment());
			}
			else if (b.getTypeString().equals("Error")) {
				err++;
			}
		}
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		int funcs = 0, fail = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			funcs++;
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			if (!r.decompileCompleted()) {
				fail++;
				println("decompile failure at " + f.getEntryPoint() + ": " + r.getErrorMessage());
			}
		}
		println(String.format("REAL: %s instructions=%d functions=%d bad_instruction_bookmarks=%d error_bookmarks=%d decompile_failures=%d",
			currentProgram.getName(), n, funcs, bad, err, fail));
	}
}
