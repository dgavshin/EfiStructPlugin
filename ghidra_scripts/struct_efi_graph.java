/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile the function at the cursor, then build data-flow graph (AST)
//@category PCode

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.GraphASTControlFlowAction;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.service.graph.*;
import ghidra.util.Msg;

public class struct_efi_graph extends GhidraScript {
	private static final String COLOR_ATTRIBUTE = "Color";
	private static final String ICON_ATTRIBUTE = "Icon";
	private static final String CODE_ATTRIBUTE = "Code";
	private static final String SYMBOLS_ATTRIBUTE = "Symbols";

	private AttributedGraph graph;
	protected HighFunction high;
	private final List<String> uefiFuncList = new ArrayList<>(List.of("EFI_LOCATE_PROTOCOL", "EFI_SMM_GET_SMST_LOCATION2",
			"EFI_LOCATE_PROTOCOL", "EFI_SMM_REGISTER_PROTOCOL_NOTIFY", "REGISTER", "EFI_INSTALL_PROTOCOL_INTERFACE"));

	public ArrayList<PcodeOpAST> defineUefiFunctions() {
		DecompInterface decomp = new DecompInterface();
		ArrayList<PcodeOpAST> callInd = new ArrayList<>();
		decomp.openProgram(this.getCurrentProgram());
		ArrayList<Function> funcWithCallInd = new ArrayList<>();
		for (Function func = this.getFirstFunction(); func != null; func = this.getFunctionAfter(func)) {
			funcWithCallInd.add(func);
		}
		for (String s : this.uefiFuncList) {
			int size = funcWithCallInd.size();
			for (int j = 0; j < size; j++) {
				DecompileResults res = decomp.decompileFunction(funcWithCallInd.get(j), 120, this.getMonitor());
				HighFunction hifunc = res.getHighFunction();
				if (hifunc == null)
					continue;
				Iterator<PcodeOpAST> pCodeIter = hifunc.getPcodeOps();
				int callIndCount = 0;
				while (pCodeIter.hasNext()) {
					PcodeOpAST pCode = pCodeIter.next();
					if (pCode.getOpcode() == PcodeOp.CALLIND) {
						callIndCount++;
						String callIndType = pCode.getInput(0).getHigh().getDataType().getName();
						if (s.compareTo("REGISTER") == 0) {
							if (callIndType.length() < 11)
								continue;
							callIndType = callIndType.substring(callIndType.length() - 9);
							char first = callIndType.charAt(0);
							if (first == '_') {
								callIndType = callIndType.substring(1);
							} else {
								callIndType = callIndType.substring(0, callIndType.length() - 1);
							}
						}
						if (callIndType.compareToIgnoreCase(s) == 0) {
							callInd.add(pCode);
						}
					}
				}
				if (callIndCount == 0) {
					funcWithCallInd.remove(j);
					j--;
					size = funcWithCallInd.size();
				}
			}
		}
		decomp.closeProgram();
		return (callInd);
	}

	private String getVarnodeKey(VarnodeAST vn) {
		PcodeOp op = vn.getDef();
		String id;
		if (op != null) {
			id = op.getSeqnum().getTarget().toString(true) + " v " +
					vn.getUniqueId();
		}
		else {
			id = "i v " + vn.getUniqueId();
		}
		return id;
	}

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		return sq.getTarget().toString(true) + " o " + op.getSeqnum().getTime();
	}

	protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getHigh().getHighFunction().getFunction().getName();
		String id = getVarnodeKey(vn);
		String colorattrib = "Red";
		if (vn.isConstant()) {
			colorattrib = "DarkGreen";
		}
		else if (vn.isRegister()) {
			colorattrib = "Blue";
		}
		else if (vn.isUnique()) {
			colorattrib = "Black";
		}
		else if (vn.isPersistant()) {
			colorattrib = "DarkOrange";
		}
		else if (vn.isAddrTied()) {
			colorattrib = "Orange";
		}
		AttributedVertex vert = graph.addVertex(id, name);
		if (vn.isInput()) {
			vert.setAttribute(ICON_ATTRIBUTE, "TriangleDown");
		}
		else {
			vert.setAttribute(ICON_ATTRIBUTE, "Circle");
		}
		vert.setAttribute(COLOR_ATTRIBUTE, colorattrib);
		return vert;
	}

	protected AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				currentProgram.getAddressFactory().getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = high.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setAttribute(ICON_ATTRIBUTE, "Square");
		return vert;
	}

	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices, VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	protected void createEdge(AttributedVertex in, AttributedVertex out) {
		graph.addEdge(in, out);
	}

	protected HashMap<String, AttributedVertex> createMainVertexes(ArrayList<PcodeOpAST> callInd)
	{
		HashMap<String, AttributedVertex> mainVertexes = new HashMap<>();
		for (PcodeOpAST pCode : callInd) {
			String funcType = pCode.getInput(0).getHigh().getDataType().getName();
			if (mainVertexes.containsKey(funcType))
				continue;
			AttributedVertex v = graph.addVertex(funcType + "id", funcType);
			v.setAttribute(ICON_ATTRIBUTE, "Square");
			mainVertexes.put(funcType, v);
		}
		return mainVertexes;
	}

	protected void buildGraph() {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		HashMap<Integer, AttributedVertex> vertices = new HashMap<>();

		ArrayList<PcodeOpAST> ops = defineUefiFunctions();
		HashMap<String, AttributedVertex> mainVertexes =  createMainVertexes(ops);
		for (PcodeOpAST op: ops)
		{
			String funcType = op.getInput(0).getHigh().getDataType().getName();
			AttributedVertex o = createOpVertex(op);
			VarnodeAST outvn = (VarnodeAST) op.getInput(1);
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					createEdge(o, outv);
					createEdge(outv, mainVertexes.get(funcType));
				}
			}

		}
	}



	@Override
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
			return;
		}
		GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
		if (graphDisplayBroker == null) {
			Msg.showError(this, tool.getToolFrame(), "GraphAST Error",
					"No graph display providers found: Please add a graph display provider to your tool");
			return;
		}

		graph = new AttributedGraph(true);

		buildGraph();
		GraphDisplay graphDisplay =
				graphDisplayBroker.getDefaultGraphDisplay(false, monitor);
		graphDisplay.setGraph(graph, "Data-flow AST", false, monitor);
		graphDisplay.defineVertexAttribute(CODE_ATTRIBUTE);
		graphDisplay.defineVertexAttribute(SYMBOLS_ATTRIBUTE);
		graphDisplay.setVertexLabel(CODE_ATTRIBUTE, GraphDisplay.ALIGN_CENTER, 40, false, 10);
		graphDisplay.setGraphDisplayListener(
				new EfiGraphDisplayListener(tool, graphDisplay, high, currentProgram));
	}
}
