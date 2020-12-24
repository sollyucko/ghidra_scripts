//TODO write a description for this script
//@author 
//@category Strings
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.*;
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
import ghidra.program.model.correlate.*;
import java.util.*;

public class FindPrintfBugFunctionName extends AnalyzePrintf {
    public void run() throws Exception {
        println((new Date()).toString());
        
        Function printf = getPrintf();
        if(printf == null) return;
        String bugString = "BUG: failure at %s:%d/%s()!\n";
        Address bugStringAddr = find(null, bugString.getBytes("US-ASCII"));
        if(bugStringAddr == null) {
            println("Could not find bug string!");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(false);
        decomp.toggleJumpLoads(false);
        decomp.toggleParamMeasures(false);
        decomp.toggleSyntaxTree(true);
        decomp.openProgram(currentProgram);
        
        Reference[] bugStringRefs = getReferencesTo(bugStringAddr);
        Set<Address> bugStringFuncs = new HashSet<>();
        for(Reference ref : bugStringRefs) {
            Function func = getFunctionContaining(ref.getFromAddress());
            if(func == null) continue;
            bugStringFuncs.add(func.getEntryPoint());
        }
        println(""+bugStringFuncs.size());
        
        Reference[] refs = getReferencesTo(printf.getEntryPoint());
        refLoop: for(Reference ref : refs) {
            if(ref == null) println("ref is null");
            Address instructionAddress = ref.getFromAddress();
            if(instructionAddress == null) println("instructionAddress is null");
            Function caller = getFunctionContaining(instructionAddress);
            if(caller == null) throw new Exception("caller is null");
            if(!caller.getName().startsWith("FUN_")) continue refLoop;
            if(!bugStringFuncs.contains(caller.getEntryPoint())) continue refLoop;
            try {
                DecompileResults res;
                try {
                    res = decomp.decompileFunction(caller, 0, monitor);
                } catch(Throwable ex) {
                    throw new Exception("error in decompiler: " + ex.toString());
                }
                if(res == null) return; // probably cancelled
                HighFunction highCaller = res.getHighFunction();
                if(highCaller == null) throw new Exception(caller.toString() + ": highCaller is null");
                Iterator<PcodeOpAST> iter;
                try {
                    iter = highCaller.getPcodeOps(instructionAddress);
                } catch(Throwable ex) {
                    throw new Exception("error in getPcodeOps: " + ex.toString());
                }
                if(iter == null) throw new Exception("iter is null");

                String fmt = null;
                String name = null;

                pcodeOpLoop: while(iter.hasNext()) {
                    PcodeOpAST op = iter.next();
                    if(op == null) println("op is null");
                    if(op.getOpcode() == PcodeOp.CALL) {
                        try {
                            if(op.getInput(1) == null) throw new Exception("fmt is missing");
                            fmt = getString(toAddr(resolveVarnode(op.getInput(1))));
                            if(!fmt.equals(bugString)) throw new Exception("wrong fmt: " + fmt);
                            if(op.getInput(4) == null) throw new Exception("name is missing");
                            name = getString(toAddr(resolveVarnode(op.getInput(4))));
                            break pcodeOpLoop;
                        } catch(Throwable ex) {
                            throw new Exception("error in resolveVarnode/toAddr/getString: " + ex.toString());
                        }
                    }
                }
                
                if(fmt == null) throw new Exception("fmt is null");
                if(name == null) throw new Exception("name is null");

                println(caller.toString() + " -> '" + name + "'");
                
                println(caller.getClass().toString());
                caller.setName(name, SourceType.ANALYSIS);
            } catch(Throwable ex) {
                //println(caller.toString() + ": " + ex.toString());
                continue refLoop;
            }
        }
        println((new Date()).toString());
    }
}
