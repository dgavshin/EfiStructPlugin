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

import static efigraph.GuidDB.GUID_DEFAULT;

/**
 * This is key unit of plugin that works with any data
 * related to the specified efi file from Ghidra project:
 * {@link MemoryBlock}, {@link ghidra.program.model.symbol.SymbolTable},
 * list of {@link EfiEntry}.
 *
 * This class implements Serializable, so it will be cached by {@link EfiCache}.
 */
class ProgramMetaData implements Serializable
{
    private final String                  name;
    private final String                  path;
    final ArrayList<EfiEntry>     functions = new ArrayList<>();

    public final static ArrayList<String> UEFI_BLOCKS =
            new ArrayList<>(Arrays.asList("regInterrupt",
                                        "locateProtocol",
                                        "installProtocol",
                                        "childSmi"));

    /**
     * This constructor stores basic data about current program and file
     * and analyzes this data to create a structure of functions and
     * protocols that are related with each other
     * @param path the path of efi file in Ghidra project
     * @param name name of efi file. Must have extension .efi.
     * @param metaBlocks data from {@link MemoryBlock} of specified program
     */
    public ProgramMetaData(String path, String name, HashMap<String, ArrayList<String>> metaBlocks)
    {
        this.name = name;
        this.path = path;

        parseBlocks(metaBlocks);
    }

    /**
     * @return the name of the file that this class belongs to
     */
    public String getName() {
        return name;
    }

    /**
     * @return list of function entries.
     * Function entries are functions specified in {@link #UEFI_BLOCKS}.
     */
    public ArrayList<EfiEntry> getFunctions() {
        return functions;
    }

    /**
     * Creates structure and links between found protocols and functions and
     * wraps each of them to {@link EfiEntry} class.
     * All functions (specified in UEFI_BLOCKS) writes to the {@link #functions}.
     *
     * @param metaBlocks data parsed by function {@link #readMemoryBlocks(Program)}
     */
    private void parseBlocks(HashMap<String, ArrayList<String>> metaBlocks) {
        for (Map.Entry<String, ArrayList<String>> entry: metaBlocks.entrySet()) {
            final EfiEntry protocol = new EfiEntry(entry.getKey());
            for (String value : entry.getValue())
            {
                String[] tmp = value.split("=");
                protocol.addReference(new EfiEntry(tmp[0], tmp[1], protocol), false);
            };
            functions.add(protocol);
        }
    }

    /**
     * @return String in format:
     * filename
     *      function1:
     *          protocol address - protocol guid
     *          protocol address - protocol guid
     *          ...
     *      ...
     *      functionN
     */
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

    /**
     * Read {@link MemoryBlock} from specified program
     * UEFI_BLOCKS consists available blocks for read
     * @param program program for read Memory Blocks
     * @return HashMap of found function and list of it's protocols
     */
    public static HashMap<String, ArrayList<String>> readMemoryBlocks(Program program)
    {
        byte[]      raw;
        Memory memory;
        MemoryBlock memoryBlock;
        HashMap<String, ArrayList<String>> blocks;

        blocks = new HashMap<>();
        memory = program.getMemory();
        for (String blockName : UEFI_BLOCKS) {
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

    /**
     * Function for parsing Memory Block 
     * @param raw
     * @return
     */
    public static ArrayList<String> parseRawBlock(byte[] raw)
    {
        String data;

        data = new String(raw);
        data = data.substring(1, data.length() - 1);
        return (new ArrayList<>(Arrays.asList(data.split(", "))));
    }

    public EfiEntry findProtocol(String name)
    {
        if (name == null)
            return null;
        for (EfiEntry entry: functions)
        {
            for (EfiEntry ref: entry.getReferences())
            {
                if (ref.getName().equals(name))
                    return ref;
                else if (ref.getGuid().equals(name) && !name.equals(GUID_DEFAULT))
                    return ref;
            }
        }
        return null;
    }
}