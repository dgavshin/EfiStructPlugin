package efigraph;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class EfiGraphProvider extends ComponentProvider {

    public static HashMap<String, Symbol> USER_SYMBOLS = new HashMap<>();

    public static final String      NAME = "Struct Efi";
    public static ProgramMetaData   PMD;
    public static PluginTool        tool;
    public static Program           program;
    public static EfiGraphPlugin    plugin;

    private final AttributedGraph   graph;
//    private final List<String>      uefiFuncList = new ArrayList<>(List.of("EFI_LOCATE_PROTOCOL", "EFI_SMM_GET_SMST_LOCATION2",
//                                        "EFI_SMM_REGISTER_PROTOCOL_NOTIFY", "REGISTER", "EFI_INSTALL_PROTOCOL_INTERFACE"));

    private static final String     COLOR_ATTRIBUTE = "Color";
    private static final String     ICON_ATTRIBUTE = "Icon";
    private HashMap<String, String> guids = new HashMap<>();

    private JPanel                  panel;
    private DockingAction           action;

    public static EfiCache          cacheTool;
    public static GuidDB            guidDB;


    public EfiGraphProvider(PluginTool tool, EfiGraphPlugin plugin, Program program) {

        super(tool, NAME, plugin.getName());
        GraphDisplay        graphDisplay;
        PluginTool          pluginTool;
        GraphDisplayBroker  graphDisplayBroker;

        EfiGraphProvider.tool = tool;
        EfiGraphProvider.program = program;
        EfiGraphProvider.plugin = plugin;
        cacheTool = new EfiCache(program, tool);
        graph = new AttributedGraph();
        pluginTool = plugin.getTool();

        setWindowMenuGroup(EfiGraphProvider.NAME);
        setWindowGroup(EfiGraphProvider.NAME);
        setDefaultWindowPosition(WindowPosition.WINDOW);
        graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
        buildGraph();

        try {
            graphDisplay = graphDisplayBroker.getDefaultGraphDisplay(true, TaskMonitor.DUMMY);
            graphDisplay.setGraph(graph, "Efi protocols", false, TaskMonitor.DUMMY);
            graphDisplay.setGraphDisplayListener(
                    new EfiGraphDisplayListener(pluginTool, graphDisplay, program));
        } catch (GraphException | CancelledException | NullPointerException e) {
            Msg.error(this, e.getMessage());
        }

        addToTool();
        buildPanel();
        createActions();
    }

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

    private List<AttributedEdge> findServices() {
        ArrayList<AttributedEdge> edges = new ArrayList<>();
        AttributedVertex in;
        AttributedVertex out;
        String           addr;

        if (PMD == null || PMD.getFunctions() == null)
            return null;
        for (EfiEntry e: PMD.getFunctions())
        {
            addr = e.getFuncAddress(program);
            in = new AttributedVertex(addr == null ? e.getName() : addr, e.getName());
            in.setAttribute("Icon", "Square");
            in.setAttribute("Color", "Red");
            graph.addVertex(in);
            for (EfiEntry entry: e.getReferences())
            {
                out = new AttributedVertex(entry.getKey(), entry.getName());
                out.setAttribute("Icon", "Circle");
                out.setAttribute("Color", "Green");
                graph.addVertex(out);
                edges.add(graph.addEdge(in, out));
            }
        };
        return edges;
    }


    void buildGraph() {
        List<AttributedVertex> globals;
//        List<AttributedEdge>   edges;
        List<AttributedVertex> protocols;

//        globals = findGlobals();
        findServices();
//        protocols = findProtocols(services);
    }


    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTextArea textArea = new JTextArea(5, 25);
        textArea.setEditable(false);
        panel.add(new JScrollPane(textArea));
        setVisible(true);
    }

    // TODO: Customize actions
    private void createActions() {
        action = new DockingAction("My Action", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Msg.showInfo(getClass(), panel, "Custom Action", EfiGraphPlugin.PROJECT_PATH);
            }
        };
        action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
        action.setEnabled(true);
        action.markHelpUnnecessary();
        dockingTool.addLocalAction(this, action);
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