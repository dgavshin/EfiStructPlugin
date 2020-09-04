package efigraph;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static efigraph.EfiGraphProvider.*;

class EfiGraphDisplayListener extends AddressBasedGraphDisplayListener {

    AttributedGraph graph;

    public EfiGraphDisplayListener(PluginTool tool, GraphDisplay display,
                                   Program program, AttributedGraph graph)
    {
        super(tool, program, display);
        this.graph = graph;
    }

    @Override
    protected List<String> getVertices(AddressSetView selection) {
        return (new ArrayList<>());
    }

    @Override
    protected AddressSet getAddressSetForVertices(List<String> vertexIds)
    {
        AddressSet set = new AddressSet();
        for (String id : vertexIds) {
            Address address = getAddressForVertexId(id);
            if (address != null) {
                set.add(address);
            }
        }
        return (set);
    }

    @Override
    protected Address getAddressForVertexId(String vertexId)
    {
        AttributedVertex v;

        Msg.info(this, "Getting the vertex address for id: " + vertexId);

        v = graph.getVertex(vertexId);
        if (v == null)
            return null;
        switch (v.getAttribute("Type"))
        {
            case "File":
                buildFileGraph((ProgramMetaData) cacheTool.getCachedFile(v.getName()), v);
                break;
            case "Protocol":
                if (LOCATE_ENTRY || INSTALL_ENTRY)
                    findReferencesFromFiles(v);
                break;
            case "Function":
                break;
        }

        return (getAddress(vertexId));
    }

    private void buildFileGraph(ProgramMetaData pmd, AttributedVertex vn)
    {
        ArrayList<AttributedVertex> vertices;
        String suffix;

        if (pmd == null)
            return;
        suffix = pmd.getName().substring(0, 4) + ": ";
        vertices = findServices(pmd, null, suffix);
        if (vertices != null)
            vertices.forEach(e -> graph.addEdge(vn, e));
    }

    private void findReferencesFromFiles(AttributedVertex v)
    {
        String           name;
        AttributedVertex vn;
        EfiEntry         target;

        name = v.getName().contains(":") ? v.getName().substring(6) : v.getName();
        target = PMD.findProtocol(name);
        if (target == null)
            return;
        EfiProgramResearcher epr = new EfiProgramResearcher(target);

        if (LOCATE_ENTRY && target.getParentProtocol().getName().equals("locateProtocol")) {
            for (Map.Entry<String, EfiEntry> e: epr.installEntries.entrySet())
            {
                Msg.info(this, "[+] Adding new vertex from " + e.getKey() + " file via Install Protocol named " + e.getValue().getName());
                if (graph.getVertex(e.getKey()) == null) {
                    vn = createThirdPartyReference(e.getKey(), e.getKey());
                    graph.addEdge(vn, v);
                }
            }
        }
        if (INSTALL_ENTRY && target.getParentProtocol().getName().equals("installProtocol"))
        {
            for (Map.Entry<String, EfiEntry> e: epr.locateEntries.entrySet())
            {
                Msg.info(this, "[+] Adding new vertex from " + e.getKey() + " file via Locate Protocol named " + e.getValue().getName());
                if (graph.getVertex(e.getKey()) == null) {
                    vn = createThirdPartyReference(e.getKey(), e.getKey());
                    graph.addEdge(v, vn);
                }
            }
        }
    }
}
