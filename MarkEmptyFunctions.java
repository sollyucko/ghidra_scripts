//Looks for functions that immediately return.
//Gives them a signature of "__cdecl inline void do_nothing(void)".
//@author Solomon Ucko
//@category Functions
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class MarkEmptyFunctions extends GhidraScript {
    private void logFunction(Function function) {
        println("Name: " + function.getName());
        println("Entry point: " + function.getEntryPoint());
    }

    private boolean checkFunction(Function function) {
        Instruction instruction = getInstructionAt​(function.getEntryPoint());
        if(instruction == null) {
            return false;
        }
        PcodeOp[] ops = instruction.getPcode();
        if(ops.length > 0 && ops[0].getOpcode() == PcodeOp.RETURN) {
            return true;
        }
        if(ops.length > 1 && ops[0].getOpcode() == PcodeOp.COPY && ops[1].getOpcode() == PcodeOp.RETURN) {
            Register outReg = currentProgram.getRegister(ops[0].getOutput());
            if(outReg == null || !outReg.isProgramCounter()) return false;

            Varnode[] inputs = ops[0].getInputs();
            assert(inputs.length == 1);
            Register inReg = currentProgram.getRegister(inputs[0]);
            if(inReg == null) return false;

            //TODO: add more architectures, or find a general method
            //AArch64, probably also 32
            if(inReg.getName().equals("w30") || inReg.getName().equals("x30")) return true;
println(inReg.getName());
            return false;
        }
        return false;
    }

    private void markFunction(Function function) throws Exception {
            function.setInline(true);
            function.setName("do_nothing", SourceType.ANALYSIS);
            function.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.ANALYSIS);
            function.setCallingConvention("__cdecl");
            function.setSignatureSource(SourceType.ANALYSIS);
    }
    
    @Override
    public void run() throws Exception {
	for(Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if(checkFunction(function)) {
                println("Marking function");
                logFunction(function);
                markFunction(function);
            }
        }
    }
}
