#TODO write a description for this script
#@author Yash
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import os, json

def get_high_function(func):
	options = DecompileOptions()
	monitor = ConsoleTaskMonitor()
	ifc = DecompInterface()
	ifc.setOptions(options)
	ifc.openProgram(getCurrentProgram())
        
	res = ifc.decompileFunction(func, 60, monitor)
	high = res.getHighFunction()
	return high
        
def dump_refined_pcode(func, high_func):
	stri = []
	
	opiter = high_func.getPcodeOps()
	
	while opiter.hasNext():
		op = opiter.next()
		stri.append(str(op))
	
	return stri
	
def allfunctions():
	func_data = []
	f_nameArr = []
	state = getState()
	currentProgram = state.getCurrentProgram()
	
    	name = currentProgram.getName()
	location = currentProgram.getExecutablePath()
	
	
	f = getFirstFunction()
	while f is not None:
		
		print "[+]Function: ", f.getName()
		f_nameArr.append(f.getName())
			
		hf = get_high_function(f)  #This returns "None"
		print("the high function returns: " + str(hf))
		
		f_pcode = dump_refined_pcode(f,hf)   	
		func_data.append(f_pcode)  #Appending the pcodes into the list

		f = getFunctionAfter(f)

allfunctions()