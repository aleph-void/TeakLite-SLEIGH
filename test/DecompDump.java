// Prints the decompiled C of every function (development aid).  Script args: <outfile>
//@category Testing
import java.io.PrintStream;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		PrintStream out = new PrintStream(getScriptArgs()[0]);
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			out.println("==== " + f.getName() + " @ " + f.getEntryPoint());
			out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "FAILED " + r.getErrorMessage());
		}
		out.close();
	}
}
