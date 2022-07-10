import sys
sys.path.append('C:\Program Files\Python2.7\Lib\site-packages')  #Important
import networkx as nx
import pydot
from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp

def buildAST(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    ifc.setSimplificationStyle("normalize")
    high = None
    try: 
        res = ifc.decompileFunction(func, 60, monitor)
        high = res.getHighFunction()
    except Exception as e: 
	print(e)
    return high

def buildGraph(graph, func, high):
    
    old = func
    opiter = getPcodeOpIterator(high)
    #opiter = high.getPcodeOps()
    
    while opiter.hasNext():
        op = opiter.next()
        vert = createOpVertex(func, op)
        graph.add_node(vert)
        graph.add_edge(old, vert)

	old = vert

def createOpVertex(func, op):
    name = op.getMnemonic()
    id = getOpKey(op)
    opcode = op.getOpcode()
    if ((opcode == PcodeOp.LOAD) or (opcode == PcodeOp.STORE)):
        vn = op.getInput(0)
        addrspace = currentProgram.getAddressFactory().getAddressSpace(vn.getOffset())
        name += ' ' + addrspace.getName()
    elif (opcode == PcodeOp.INDIRECT):
        vn = op.getInput(1)
        if (vn != None):
            indOp = high.getOpRef(vn.getOffset())
            if (indOp != None):
                name += " (" + indOp.getMnemonic() + ")"
    return "{}_{}".format(name, id)
    

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getOpKey(op):  #id for opcodes to make all the nodes different
    sq = op.getSeqnum()
    id = str(sq.getTarget()) + " o " + str(op.getSeqnum().getTime())
    return id

def getPcodeOpIterator(high):
    return high.getPcodeOps()

def main():
    graph = nx.DiGraph()
    listing = currentProgram.getListing()
#Give the function name here
    fname = "Name_of_the_function"  #Give the name of the function you want to generate a graph
    func = getGlobalFunctions(fname)[0]

    high = buildAST(func)
    print(high)
    buildGraph(graph, func, high)		


    dot_data = nx.nx_pydot.to_pydot(graph)
    svg = pydot.graph_from_dot_data(dot_data.to_string())[0].create_svg()
    
    name = currentProgram.getName()

    svg_path = "C:\\" + name + ".svg"
    f = open(svg_path, 'w')
    f.write(svg)
    f.close()

    print("Wrote pydot SVG of graph to: {}\nNodes: {}, Edges: {}".format(svg_path, len(graph.nodes), len(graph.edges)))

main()
