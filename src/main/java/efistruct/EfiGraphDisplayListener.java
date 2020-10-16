package efistruct;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.util.Msg;

import java.util.*;

import static efistruct.EfiGraphProvider.*;
import static efistruct.EfiProgramResearcher.INSTALL_PROTOCOL;
import static efistruct.EfiProgramResearcher.LOCATE_PROTOCOL;

class EfiGraphDisplayListener extends AddressBasedGraphDisplayListener {

    AttributedGraph graph;

    public EfiGraphDisplayListener(PluginTool tool, GraphDisplay display,
                                   Program program, AttributedGraph graph) {
        super(tool, program, display);
        this.graph = graph;
    }

    @Override
    protected List<String> getVertices(AddressSetView selection) {
        return (new ArrayList<>());
    }

    @Override
    protected AddressSet getAddressSetForVertices(List<String> vertexIds) {
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
    protected Address getAddressForVertexId(String vertexId) {
        AttributedVertex v;

        Msg.info(this, "Getting the vertex address for id: " + vertexId);

        v = graph.getVertex(vertexId);
        if (v == null)
            return null;
        switch (v.getAttribute("Type")) {
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

    private void buildFileGraph(ProgramMetaData pmd, AttributedVertex vn) {
        ArrayList<AttributedVertex> vertices;
        HashMap<String, HashMap<String, String>> attributes;
        String suffix;

        if (pmd == null)
            return;

        attributes = getRandomAttributes(pmd.getName());
        suffix = pmd.getName().substring(0, 4) + ": ";
        vertices = findServices(pmd, null, suffix, attributes);
        if (vertices != null)
            vertices.forEach(e -> graph.addEdge(vn, e).putAttributes(attributes.get("Edge")));
    }

    private void findReferencesFromFiles(AttributedVertex v)
    {
        EfiProgramResearcher epr;
        String               name;
        EfiEntry             target;

        name = v.getName().contains(":") ? v.getName().substring(6) : v.getName();
        if (v.getAttributeMap().containsKey("Source")) {
            ProgramMetaData pmd = (ProgramMetaData) cacheTool.getCachedFile(v.getAttribute("Source"));
            target = pmd.findProtocol(name);
        }
        else
            target = EfiGraphProvider.PMD.findProtocol(name);
        epr = new EfiProgramResearcher(target);
        if (target == null)
            return;
        handleReference(epr.founded_programs, v);
    }

    private void handleReference(Set<ProgramMetaData> ref, AttributedVertex v)
    {
        AttributedVertex vn;

        for (ProgramMetaData e: ref)
        {
            Msg.info(this, "[+] Adding new vertex from " + e.getName());
            if (graph.getVertex(e.getName()) == null && !e.getName().equals(EfiGraphProvider.program.getName())) {
                vn = new EfiEntry(e.getName(), "File").createVertex("", program, DEFINED_COLORS);
                graph.addEdge(v, vn).putAttributes(DEFINED_COLORS.get("Edge"));
            }
        }
    }
}
