package efigraph;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

class ProgramMetaData implements Serializable
{
    private final String                  name;
    private final String                  path;
    private final ArrayList<EfiEntry>     functions = new ArrayList<>();

    public final static ArrayList<String> uefiBlocks = new ArrayList<>(Arrays.asList("regInterrupt",
                                                                                        "locateProtocol",
                                                                                        "installProtocol",
                                                                                        "childSmi"));


    public ProgramMetaData(String path, String name, HashMap<String, ArrayList<String>> metaBlocks)
    {
        this.name = name;
        this.path = path;

        parseBlocks(metaBlocks);
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    public ArrayList<EfiEntry> getFunctions() {
        return functions;
    }

    private void parseBlocks(HashMap<String, ArrayList<String>> metaBlocks) {
        for (Map.Entry<String, ArrayList<String>> entry: metaBlocks.entrySet()) {
            final EfiEntry protocol = new EfiEntry(entry.getKey());
            for (String value : entry.getValue())
            {
                String[] tmp = value.split("=");
                protocol.addReference(new EfiEntry(tmp[0], tmp[1], protocol));
            };
            functions.add(protocol);
        }
    }

    @Override
    public String toString() {
        StringBuilder	str;

        str = new StringBuilder();
        str.append(this.name).append("\n");
        for (EfiEntry entry: functions)
        {
            str.append("\t").append(entry.getName()).append("\n");
            for (EfiEntry reference: entry.getReferences())
            {
                str.append("\t\t").append(reference.getName()).append(" - ");
                str.append(reference.getFuncAddress(EfiGraphProvider.program)).append("\n");
            }
        }
        return str.toString();
    }

    public static HashMap<String, ArrayList<String>> readMemoryBlocks(Program program)
    {
        byte[]      raw;
        Memory memory;
        MemoryBlock memoryBlock;
        HashMap<String, ArrayList<String>> blocks;

        blocks = new HashMap<>();
        memory = program.getMemory();
        for (String blockName : uefiBlocks) {
            memoryBlock = memory.getBlock(blockName);
            if (memoryBlock != null) {
                raw = new byte[(int) memoryBlock.getSize()];
                try {
                    memoryBlock.getBytes(memoryBlock.getStart(), raw);
                    blocks.put(blockName, parseRawBlock(raw));
                } catch (MemoryAccessException e) {
                    Msg.debug(program, "[-] No such block in program " + program.getName());
                }
            }
        }
        return (blocks);
    }


    public static ArrayList<String> parseRawBlock(byte[] raw)
    {
        String data;

        data = new String(raw);
        data = data.substring(1, data.length() - 1);
        return (new ArrayList<>(Arrays.asList(data.split(", "))));
    }
}