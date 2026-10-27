// Prints the p-code of instruction words (hex 4 digits, little-endian value) placed at word address 0x100.
// Script args: <hex word> ...
//@category Testing
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address a = currentProgram.getAddressFactory().getAddressSpace("CODE").getAddress(0x200);
		for (String s : getScriptArgs()) {
			int w = Integer.parseInt(s, 16);
			clearListing(a, a.add(8));
			setBytes(a, new byte[] { (byte) w, (byte) (w >> 8), 0, 0 });
			disassemble(a);
			Instruction ins = getInstructionAt(a);
			println(String.format("%04x  %s   (len %d, fallthrough %s)", w, ins, ins.getLength(), ins.getFallThrough()));
			for (PcodeOp op : ins.getPcode()) {
				println("     " + op);
			}
		}
	}
}
