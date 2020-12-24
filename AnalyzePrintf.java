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
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.regex.*;

class ResolveVarnodeException extends Exception {
    public String message;
    public ResolveVarnodeException(String message) { this.message = message; }
    public String toString() { return "ResolveVarnodeException: " + this.message; }
}

public class AnalyzePrintf extends GhidraScript {
    protected boolean checkCalleeSignature(FunctionSignature sig) {
        ParameterDefinition[] params = sig.getArguments();
        if(params.length != 1) {
            println("Bad parameter count");
            return false;
        }
        if(!params[0].getDataType().getName().equals("char *")) {
            println("Bad parameter type");
            println(params[0].getDataType().getName());
            return false;
        }
        if(!sig.hasVarArgs()) {
            println("Missing varargs");
            return false;
        }
        return true;
    }
    
    protected long resolveVarnode(Varnode varnode) throws ResolveVarnodeException {
        if(varnode.isConstant()) return varnode.getOffset();
        PcodeOp def = varnode.getDef();
        if(def == null) throw new ResolveVarnodeException("def is null, varnode = " + varnode.toString());
        switch(def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
                return resolveVarnode(def.getInput(0));
            case PcodeOp.PTRSUB: return resolveVarnode(def.getInput(1)) - resolveVarnode(def.getInput(0));
            case PcodeOp.PTRADD: {
                long sum = 0;
                for(Varnode input : def.getInputs()) {
                    sum += resolveVarnode(input);
                }
                return sum;
            }
            case PcodeOp.MULTIEQUAL: {
                Varnode firstInput = def.getInput(0);
                long result = resolveVarnode(firstInput);
                for(Varnode input : def.getInputs()) {
                    if(!input.equals(firstInput)) {
                        long newResult = resolveVarnode(input);
                        if(newResult != result) {
                            throw new ResolveVarnodeException("Unresolvable MULTIEQUAL: " + result + " vs " + newResult + ": " + def.toString());
                        }
                    }
                }
                return result;
            }
            default: throw new ResolveVarnodeException("Unrecognized opcode: " + def.toString());
        }
    }
    
    protected String getString(Address address) throws Exception {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        byte b;
        while((b = getByte(address)) != 0) {
            data.write(b);
            address = address.next();
        }
        return data.toString("US-ASCII");
    }

    protected int count(String str, char ch) {
        int result = 0;
        for(int i = 0; i < str.length(); ++i) {
            if(str.charAt(i) == ch) ++result;
        }
        return result;
    }

    protected Function getPrintf() {
        List<Function> callees = getGlobalFunctions("printf");
        if(callees.size() == 0) {
            println("No global functions named 'printf' found.");
            return null;
        }
        if(callees.size() > 1) {
            println(callees.size() + " global functions named 'printf' found.");
            return null;
        }
        Function callee = callees.get(0);
        FunctionSignature sig = callee.getSignature();
        if(!checkCalleeSignature(sig)) return null;
        return callee;
    }

    public void run() throws Exception {
        Function callee = getPrintf();
        if(callee == null) return;

        /**********
         * MODIFY *
         **********/
        // arch-dependent
        DataType CHAR = SignedCharDataType.dataType;
        DataType PCHAR = PointerDataType.getPointer(CHAR, currentProgram.getDataTypeManager());
        DataType VOID = VoidDataType.dataType;
        DataType PVOID = PointerDataType.getPointer(VOID, currentProgram.getDataTypeManager());
        DataType SHORT = ShortDataType.dataType;
        DataType USHORT = UnsignedShortDataType.dataType;
        DataType INT = IntegerDataType.dataType;
        DataType UINT = UnsignedIntegerDataType.dataType;
        DataType LONGLONG = LongLongDataType.dataType;
        DataType ULONGLONG = UnsignedLongLongDataType.dataType;

        Pattern REGEX = Pattern.compile("%[\\d*.#-]*(?<end>[hlLz]*.)");

        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(false);
        decomp.toggleJumpLoads(false);
        decomp.toggleParamMeasures(false);
        decomp.toggleSyntaxTree(true);
        decomp.openProgram(currentProgram);
        
        Reference[] refs = getReferencesTo(callee.getEntryPoint());
        refLoop: for(Reference ref : refs) {
            Address instructionAddress = ref.getFromAddress();
            Function caller = getFunctionContaining(instructionAddress);
            try {
                DecompileResults res = decomp.decompileFunction(caller, 0, monitor);
                HighFunction highCaller = res.getHighFunction();
                Iterator<PcodeOpAST> iter = highCaller.getPcodeOps(instructionAddress);

                //println(caller.toString());

                String fmt = null;


                while(iter.hasNext()) {
                     PcodeOpAST op = iter.next();
                     if(op.getOpcode() == PcodeOp.CALL) {
                         fmt = getString(toAddr(resolveVarnode(op.getInput(1))));
                         break;
                     }
                }

                List<ParameterDefinitionImpl> args = new ArrayList<>();
                args.add(new ParameterDefinitionImpl("fmt", PCHAR, ""));

                // todo: parse format string
                Matcher matcher = REGEX.matcher(fmt);
                while(matcher.find()) {
                    String specifier = matcher.group();
                    String specifierEnd = matcher.group("end");
                    for(int i = 0; i < count(specifier, '*'); ++i) {
                        args.add(new ParameterDefinitionImpl("", INT, ""));
                    }
                    /**********
                     * MODIFY *
                     **********/
                    // arch-dependent
                    switch(specifierEnd) {
                        case "s":
                             args.add(new ParameterDefinitionImpl("", PCHAR, ""));
                             break;
                        case "c":
                             args.add(new ParameterDefinitionImpl("", CHAR, ""));
                             break;
                        case "hd":
                        case "hi":
                             args.add(new ParameterDefinitionImpl("", SHORT, ""));
                             break;
                        case "hu":
                        case "hx":
                             args.add(new ParameterDefinitionImpl("", USHORT, ""));
                             break;
                        case "d":
                        case "i":
                             args.add(new ParameterDefinitionImpl("", INT, ""));
                             break;
                        case "u":
                        case "x":
                        case "o":
                             args.add(new ParameterDefinitionImpl("", UINT, ""));
                             break;
                        case "Li":
                        case "li":
                        case "lli":
                        case "Ld":
                        case "ld":
                        case "lld":
                             args.add(new ParameterDefinitionImpl("", LONGLONG, ""));
                             break;
                        case "lu":
                        case "llu":
                        case "Lu":
                        case "zu":
                        case "lx":
                        case "llx":
                        case "Lx":
                        case "zx":
                             args.add(new ParameterDefinitionImpl("", ULONGLONG, ""));
                             break;
                        case "p":
                             args.add(new ParameterDefinitionImpl("", PVOID, ""));
                             break;
                        case "%":
                             break;
                        default:
                             println(caller.toString());
                             println("Unsupported specifier: " + specifier + ", in " + fmt);
                             continue refLoop;
                    }
                }

                FunctionDefinitionDataType newSig = new FunctionDefinitionDataType("printf");
                newSig.setArguments(args.toArray(new ParameterDefinitionImpl[0]));
                newSig.setReturnType(INT);
                newSig.setVarArgs(false);

                HighFunctionDBUtil.writeOverride​(callee, instructionAddress, newSig);
            } catch(Throwable ex) {
                println(caller.toString());
                println(ex.toString());
                continue refLoop;
            }
        }
    }
}
