package efigraph;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
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
import java.util.function.UnaryOperator;


public class EfiGraphProvider extends ComponentProvider {

    public static HashMap<String, Symbol> USER_SYMBOLS = new HashMap<>();
    private static final Icon LOGO = ResourceManager.loadImage("images/logo.png");

    public static boolean LOCATE_ENTRY = false;
    public static boolean INSTALL_ENTRY = false;
    public static int     ID_COUNTER = 0;

    public static final String      NAME = "Struct Efi";
    public static ProgramMetaData   PMD;
    public static PluginTool        tool;
    public static Program           program;
    public static EfiGraphPlugin    plugin;
    public static EfiGUI            gui;
    public static AttributedGraph   graph;
    private final JPanel            panel;
    public static EfiCache          cacheTool;
    public static GuidDB            guidDB;

    public static String            TYPE = "Type";
    public static String            COLOR = "Color";
    public static String            ICON = "Icon";

    public static HashMap<String, HashMap<String, String>> DEFINED_COLORS = new HashMap<>()
    {
        {
            put("Edge", new HashMap<>() {{ put(COLOR, "DarkCyan"); }});
            put("Function", new HashMap<>(){{ put(COLOR, "0x4169E1"); put(ICON, "Circle"); put(TYPE, "Function");}});
            put("Protocol", new HashMap<>() {{ put(COLOR, "0x6A5ACD"); put(ICON, "Square"); put(TYPE, "Protocol");}});
            put("File", new HashMap<>() {{ put(COLOR, "OrangeRed"); put(ICON, "Polygon"); put(TYPE, "File");}});
        }
    };

    public static HashMap<String, HashMap<String, String>> getRandomAttributes(String filename)
    {
        Function<Color, String> toHex = (Color color) ->
                "0x" + String.format("%02X%02X%02X",color.getRed(), color.getGreen(), color.getBlue());


        HashMap<String, HashMap<String, String>> attributes;
        Color base;

        Color protocolColor;
        Color edgeColor;

        attributes = new HashMap<>();
        base = new Color(
                                    (int) (Math.random() * 1000.0)  % 256,
                                    (int) (Math.random() * 1000.0)  % 256,
                                    (int) (Math.random() * 1000.0)  % 256
                                 );
        edgeColor = base.brighter();
        protocolColor = base.darker();

        attributes.put("Function", new HashMap<>(){{ put(COLOR, toHex.apply(base)); put(ICON, "Circle"); put(TYPE, "Function"); put("Source", filename);}});
        attributes.put("Protocol", new HashMap<>(){{ put(COLOR, toHex.apply(protocolColor)); put(ICON, "Square"); put(TYPE, "Protocol"); put("Source", filename);}});
        attributes.put("Edge", new HashMap<>() {{ put(COLOR, toHex.apply(edgeColor));put("Source", filename); }});
        return attributes;
    }

    /**
     * This class is responsible for drawing the graph {@link #buildGraph()},
     * initializing the cache {@link EfiCache},
     * creating the user interface {@link EfiGUI}.
     *
     * @param tool {@link PluginTool}
     * @param plugin {@link EfiGraphProvider}
     * @param program that is opened by the user
     */

    public EfiGraphProvider(PluginTool tool, EfiGraphPlugin plugin, Program program) {

        super(tool, NAME, plugin.getName());

        EfiGraphProvider.tool = tool;
        EfiGraphProvider.program = program;
        EfiGraphProvider.plugin = plugin;

        getUserSymbols(program).forEach(e -> USER_SYMBOLS.put(e.getName(), e));
        cacheTool = new EfiCache(program.getDomainFile().getPathname(), program.getName());
        guidDB = EfiCache.guidDB;
        PMD = cacheTool.PMD;
        graph = new AttributedGraph();

        setWindowMenuGroup(EfiGraphProvider.NAME);
        setIcon(LOGO);
        setWindowGroup(EfiGraphProvider.NAME);
        setDefaultWindowPosition(WindowPosition.WINDOW);
        buildGraph();

        addToTool();
        gui = new EfiGUI();
        panel = gui.getDialogPane();
        panel.setSize(500, 310);
        createActions();
        setVisible(false);
    }

    /**
     * This method looks for global service in current {@link #program}
     * like gSmst, gBS, gRS.
     * @return list of vertexes added to the graph
     */
    ArrayList<AttributedVertex> findGlobals()
    {
        ArrayList<AttributedVertex> globals;
        String key;
        String name;

        globals = new ArrayList<>();
        for (Map.Entry<String, Symbol> entry: USER_SYMBOLS.entrySet()) {
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
     * @param pmd class that contains functions and references
     * @param program on the basis of which vertices will be added
     * @param suffix is a 4 first chars of program name before vertex id
     *               and vertex name to avoid the similar names in not
     *               similar programs
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
        for (EfiEntry e: pmd.getFunctions())
        {
            in = e.createVertex(suffix, program, attributes);
            for (EfiEntry entry: e.getReferences())
            {
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
        /*
        TODO: create links between globals and function vertices.
        */
//        List<AttributedVertex> globals;
//        List<AttributedEdge>   edges;
//        HashMap<EfiEntry, AttributedVertex> protocols;

//        globals = findGlobals();
        findServices(PMD, program, "", DEFINED_COLORS);
//        protocols = findProtocols(services);
    }

    /**
     * Creating button actions in GUI.
     */
    private void createActions() {
        gui.getBuildButton().addActionListener(e -> {
            LOCATE_ENTRY = gui.getLocateCheckBox().isSelected();
            INSTALL_ENTRY = gui.getInstallCheckBox().isSelected();
            displayGraph();
        });
    }

    /**
     * Finds default graph plugin and creates graph window
     */
    public static void displayGraph()
    {
        GraphDisplay        graphDisplay;
        PluginTool          pluginTool;
        GraphDisplayBroker  graphDisplayBroker;

        pluginTool = plugin.getTool();
        graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
        try {
            graphDisplay = graphDisplayBroker.getDefaultGraphDisplay(true, TaskMonitor.DUMMY);
            graphDisplay.setGraph(graph, "Efi protocols", true, TaskMonitor.DUMMY);
            graphDisplay.setGraphDisplayListener(
                    new EfiGraphDisplayListener(pluginTool, graphDisplay, program, graph));
        } catch (GraphException | CancelledException | NullPointerException e) {
            Msg.error(program, e.getMessage());
        }
    }

    /**
     * Retrieving all user symbols
     * @param program program for retrieving symbols from Symbol Table
     * @return list of symbols in specified program with {@link SourceType#USER_DEFINED}
     */
    public static ArrayList<Symbol> getUserSymbols(Program program) {
        ArrayList<Symbol> symbols = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true))
            if (symbol.getSource() == SourceType.USER_DEFINED)
                symbols.add(symbol);
        return (symbols);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    @Override
    public boolean isActive() {
        return super.isActive();
    }
}