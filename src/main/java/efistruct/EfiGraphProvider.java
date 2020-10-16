package efistruct;

import docking.WindowPosition;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static efistruct.EfiGraphPlugin.*;
import static ghidra.graph.program.ProgramGraphPlugin.MENU_GRAPH;


public class EfiGraphProvider extends ComponentProviderAdapter {

	private static final Icon LOGO = ResourceManager.loadImage("images/logo.png");

	public static boolean LOCATE_ENTRY = true;
	public static boolean INSTALL_ENTRY = true;

	public static final String NAME = "Struct Efi";
	public static PluginTool tool;
	public static Program program;
	public static EfiGraphPlugin plugin;
	public static AttributedGraph graph;
	public static GuidDB guidDB;
	public static EfiCache cacheTool;
	private static GraphDisplayProvider defaultGraphService;
	public static ProgramMetaData PMD;

	public static String TYPE = "Type";
	public static String COLOR = "Color";
	public static String ICON = "Icon";

	public static HashMap<String, HashMap<String, String>> DEFINED_COLORS = new HashMap<>() {
		{
			put("Edge", new HashMap<>() {{
				put(COLOR, "DarkCyan");
			}});
			put("Function", new HashMap<>() {{
				put(COLOR, "0x4169E1");
				put(ICON, "Circle");
				put(TYPE, "Function");
			}});
			put("Protocol", new HashMap<>() {{
				put(COLOR, "0x6A5ACD");
				put(ICON, "Square");
				put(TYPE, "Protocol");
			}});
			put("File", new HashMap<>() {{
				put(COLOR, "OrangeRed");
				put(ICON, "Polygon");
				put(TYPE, "File");
			}});
		}
	};

	/**
	 * This class is responsible for drawing the graph {@link #buildGraph()},
	 * initializing the cache {@link EfiCache},
	 *
	 * @param tool    {@link PluginTool}
	 * @param plugin  {@link EfiGraphProvider}
	 * @param program that is opened by the user
	 */

	public EfiGraphProvider(PluginTool tool, EfiGraphPlugin plugin, Program program) {
		super(tool, NAME, plugin.getName());

		EfiGraphProvider.tool = tool;
		EfiGraphProvider.program = program;
		EfiGraphProvider.plugin = plugin;

		graph = new AttributedGraph();
		getUserSymbols(program).forEach(e -> USER_SYMBOLS.put(e.getName(), e));
		cacheTool = new EfiCache(program.getDomainFile().getPathname(), program.getName(), true);
		guidDB = EfiCache.guidDB;
		PMD = cacheTool.PMD;

		setVisible(false);
		setDefaultWindowPosition(WindowPosition.LEFT);
		addToTool();
		buildGraph();
		createActions();
	}

	/**
	 * This method looks for global service in current {@link #program}
	 * like gSmst, gBS, gRS.
	 *
	 * @return list of vertexes added to the graph
	 */
	ArrayList<AttributedVertex> findGlobals() {
		ArrayList<AttributedVertex> globals;
		String key;
		String name;

		globals = new ArrayList<>();
		for (Map.Entry<String, Symbol> entry : USER_SYMBOLS.entrySet()) {
			name = entry.getKey();
			if (name.matches("gBS_.+?") || name.matches("gSmst_.+?")) {
				key = entry.getValue().getAddress().toString();
				globals.add(new AttributedVertex(key, name));
				Msg.info(this, "[+] New vertex ID: " + key);
			}
		}
		globals.forEach(e -> e.setAttribute("Icon", "Square"));
		globals.forEach(e -> e.setAttribute("Color", "Blue"));
		globals.forEach(graph::addVertex);

		return (globals);
	}

	/**
	 * This method creates main vertices from {@link ProgramMetaData#functions},
	 * child vertices from references, finally creates edges and add all of this
	 * to graph
	 *
	 * @param pmd     class that contains functions and references
	 * @param program on the basis of which vertices will be added
	 * @param suffix  is a 4 first chars of program name before vertex id
	 *                and vertex name to avoid the similar names in not
	 *                similar programs
	 * @return created and added to graph function vertices
	 */
	public static ArrayList<AttributedVertex> findServices(ProgramMetaData pmd,
														   Program program,
														   String suffix,
														   HashMap<String, HashMap<String, String>> attributes) {
		ArrayList<AttributedVertex> vertices = new ArrayList<>();
		AttributedVertex in;
		AttributedVertex out;

		if (pmd == null || pmd.getFunctions() == null)
			return null;
		for (EfiEntry e : pmd.getFunctions()) {
			in = e.createVertex(suffix, program, attributes);
			for (EfiEntry entry : e.getReferences()) {
				out = entry.createVertex(suffix, program, attributes);
				graph.addVertex(out);
				graph.addEdge(in, out).putAttributes(attributes.get("Edge"));
			}
			vertices.add(in);
		}
		return vertices;
	}

	/**
	 * Main method for building graph and creating links between
	 * all vertices in current program.
	 */
	void buildGraph() {
		findServices(PMD, program, "", DEFINED_COLORS);
	}

	/**
	 * Creating button actions in GUI.
	 */
	private void createActions() {
		tool.setMenuGroup(new String[]{"Graph", "EFI Graph"}, "Graph");

		new ActionBuilder("Graph Code Flow", getName())
				.menuPath(MENU_GRAPH, "EFI Struct", "Show graph")
				.menuGroup("Graph", "A")
				.onAction(c -> displayGraph())
				.buildAndInstall(tool);
		new ActionBuilder("EFI Graph", getName())
				.menuPath(MENU_GRAPH, "EFI Struct", "Show tree")
				.menuGroup("Graph", "B")
				.onAction(c -> setVisible(true))
				.buildAndInstall(tool);
		new ActionBuilder("Graph Code Flow", getName())
				.menuPath(MENU_GRAPH, "EFI Struct", "Delete EFI Cache")
				.menuGroup("Graph", "C")
				.onAction(c -> askDelete())
				.enabledWhen(c -> cacheTool != null)
				.buildAndInstall(tool);
	}

	public static void askDelete() {
		String title;
		String question;

		title = "Delete cache files";
		question = "You want to delete all cached files from \n" + cacheTool.CACHE_FOLDER;
		if (OptionDialog.showYesNoDialog(null, title, question) == OptionDialog.OPTION_ONE)
			EfiCache.deleteCacheFolder(cacheTool.CACHE_FOLDER);
	}

	/**
	 * Finds default graph plugin and creates graph window
	 */
	public static void displayGraph() {
		GraphDisplay graphDisplay;
		PluginTool pluginTool;
		GraphDisplayBroker graphDisplayBroker;

		pluginTool = plugin.getTool();
		graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
		defaultGraphService = graphDisplayBroker.getDefaultGraphDisplayProvider();
		try {
			graphDisplay = graphDisplayBroker.getDefaultGraphDisplay(true, TaskMonitor.DUMMY);
			graphDisplay.setGraph(graph, "Efi protocols", true, TaskMonitor.DUMMY);
			graphDisplay.setGraphDisplayListener(
					new EfiGraphDisplayListener(pluginTool, graphDisplay, program, graph));
		} catch (GraphException | CancelledException | NullPointerException e) {
			Msg.error(program, e.getMessage());
		}
	}

	public static HashMap<String, HashMap<String, String>> getRandomAttributes(String filename) {
		Function<Color, String> toHex = (Color color) ->
				"0x" + String.format("%02X%02X%02X", color.getRed(), color.getGreen(), color.getBlue());


		HashMap<String, HashMap<String, String>> attributes;
		Color base;

		Color protocolColor;
		Color edgeColor;

		attributes = new HashMap<>();
		base = new Color(
				(int) (Math.random() * 1000.0) % 256,
				(int) (Math.random() * 1000.0) % 256,
				(int) (Math.random() * 1000.0) % 256
		);
		edgeColor = base.brighter();
		protocolColor = base.darker();

		attributes.put("Function", new HashMap<>() {{
			put(COLOR, toHex.apply(base));
			put(ICON, "Circle");
			put(TYPE, "Function");
			put("Source", filename);
		}});
		attributes.put("Protocol", new HashMap<>() {{
			put(COLOR, toHex.apply(protocolColor));
			put(ICON, "Square");
			put(TYPE, "Protocol");
			put("Source", filename);
		}});
		attributes.put("Edge", new HashMap<>() {{
			put(COLOR, toHex.apply(edgeColor));
			put("Source", filename);
		}});
		return attributes;
	}

	@Override
	public JComponent getComponent() {
		return treeProvider.getComponent();
	}

	@Override
	public boolean isActive() {
		return super.isActive();
	}
}