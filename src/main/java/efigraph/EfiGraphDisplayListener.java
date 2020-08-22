package efigraph;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.GraphDisplay;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

class EfiGraphDisplayListener extends AddressBasedGraphDisplayListener {


    public EfiGraphDisplayListener(PluginTool tool, GraphDisplay display,
                                   Program program) {
        super(tool, program, display);
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
        Msg.info(this, "Get address vertex for id: " + vertexId);
        return (getAddress(vertexId));
    }
}
