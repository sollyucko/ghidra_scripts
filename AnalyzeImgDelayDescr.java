//TODO write a description for this script
//@author 
//@category Analysis
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

public class AnalyzeImgDelayDescr extends GhidraScript {
    public void run() throws Exception {
        DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
        DataType dt_code = new FunctionDefinitionDataType("code");
        DataType dt_ptr_code = PointerDataType.getPointer(dt_code, dataTypeManager);
        DataType dt_ibo64 = new ImageBaseOffset64DataType(dataTypeManager);
        DataType dt_qword = new QWordDataType(dataTypeManager);

        Listing listing = currentProgram.getListing();
        List<Address> addrs = new ArrayList<Address>();
        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();
            if(data.getDataType().getName().equals("ImgDelayDescr")) {
                println("data.getAddress()=" + data.getAddress());
                Address szName = (Address)data.getComponentAt(4).getValue();
                Address phmod = (Address)data.getComponentAt(8).getValue();
                Address pIAT = (Address)data.getComponentAt(12).getValue();
                Address pINT = (Address)data.getComponentAt(16).getValue();
                Address pBoundIAT = (Address)data.getComponentAt(20).getValue();
                
                Data name = getDataAt(szName);
                String nameStr = (String) name.getValue();
                String nameRepr = name.getDefaultValueRepresentation();
                println("nameStr=" + nameStr);
                println("nameRepr=" + nameRepr);
                createLabel(data.getMinAddress(), "ImgDelayDescr_" + nameRepr, true);
                createLabel(phmod, "ImgDelayDescr_Module_Handle_" + nameRepr, true);
                createLabel(pIAT, "ImgDelayDescr_IAT_" + nameRepr, true);
                createLabel(pINT, "ImgDelayDescr_INT_" + nameRepr, true);
                createLabel(pBoundIAT, "ImgDelayDescr_Bound_IAT_" + nameRepr, true);
                
                for(int i = 0; !monitor.isCancelled(); ++i) {
                    try {
                        Address addrIatEntry = pIAT.add(i*8);
                        println("addrIatEntry="+addrIatEntry);
                        Address addrIntEntry = pINT.add(i*8);
                        println("addrIntEntry="+addrIntEntry);
                        Data iatOrig = getDataAt(addrIatEntry);
                        println("iatOrig="+iatOrig);
                        if(iatOrig.getDataType().getName().equals("qword")) {
                            removeData(iatOrig);
                            createData(addrIatEntry, dt_ptr_code);
                        }
                        Address iatEntry = (Address) getDataAt(addrIatEntry).getValue();
                        println("iatEntry="+iatEntry);
                        if(iatEntry.getOffset() == 0)
                            break;
                        Data intOrig = getDataAt(addrIntEntry);
                        println("intOrig="+iatOrig);
                        String funcNameValue, funcNameRepr;
                        if((intOrig.getByte(7) & 0x80) != 0) {
                            if(intOrig.getDataType().getName().equals("ImageBaseOffset64")) {
                                removeData(intOrig);
                                createData(addrIntEntry, dt_qword);
                            }
                            Scalar intEntry = (Scalar) getDataAt(addrIntEntry).getValue();
                            println("intEntry="+intEntry);
                            long num = intEntry.getUnsignedValue() - 0x80_00_00_00_00_00_00_00L;
                            funcNameRepr = funcNameValue = nameStr + "::Ordinal_" + num;
                        } else {
                            if(intOrig.getDataType().getName().equals("qword")) {
                                removeData(intOrig);
                                createData(addrIntEntry, dt_ibo64);
                            }
                            Address intEntry = (Address) getDataAt(addrIntEntry).getValue();
                            println("intEntry="+intEntry);
                            Data funcName = getDataAt(intEntry).getComponentAt(2);
                            println("funcName="+funcName);
                            funcNameRepr = funcName.getDefaultValueRepresentation();
                            funcNameValue = (String) funcName.getValue();
                            createLabel(intEntry, "IMAGE_IMPORT_BY_NAME_" + funcNameRepr, true);
                        }
                        println("funcNameValue="+funcNameValue);
                        println("funcNameRepr="+funcNameRepr);
                        createLabel(iatEntry, funcNameValue, true, SourceType.IMPORTED);
                    } catch(Exception e) {
                        println("!!!" + e);
                        return;
                    }
                }
            }
        }
    }
}
