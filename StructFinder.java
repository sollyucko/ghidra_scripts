//TODO write a description for this script
//@author 
//@category Data Types
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
import ghidra.program.model.correlate.*;
import java.util.*;

public class StructFinder extends GhidraScript {
    public void run() throws Exception {
        int offset = askInt("Offset", "The offset of the structure field");
        Iterator<Structure> structures = currentProgram.getDataTypeManager().getAllStructures();
        while(structures.hasNext()) {
            Structure structure = structures.next();
            DataTypeComponent component = structure.getComponentAt(offset);
            if(component == null) continue;
            if(component.getDataType().getName() == "undefined") continue;
            println("@ 0x" + Integer.toHexString(component.getOffset()) + ": " + structure.getName() + "." + component.getFieldName() + ": " + component.getDataType().getName());
        }
    }
}
