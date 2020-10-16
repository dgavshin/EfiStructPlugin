package efistruct;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.json.JSONException;
import org.json.JSONObject;

import static efistruct.GuidDB.GUID_DEFAULT;

/**
 * This is key unit of plugin that works with any data
 * related to the specified efi file from Ghidra project:
 * {@link MemoryBlock}, {@link ghidra.program.model.symbol.SymbolTable},
 * list of {@link EfiEntry}.
 * <p>
 * This class implements Serializable, so it will be cached by {@link EfiCache}.
 */
public class ProgramMetaData implements Serializable {
	public static ArrayList<String> INVALID_NAMES = new ArrayList<>(Arrays.asList("None", "Unknown", null));
	public static ArrayList<String> INVALID_ADDRESSES = new ArrayList<>(Arrays.asList("00000000", "0000000000000000", null));
	public static String METABLOCK_NAME = "metaBlock";

	private final String name;
	private final String path;
	final ArrayList<EfiEntry> functions = new ArrayList<>();

	public static final ArrayList<String> UEFI_BLOCKS =
			new ArrayList<>(Arrays.asList("interrupts", "locate protocol", "install protocol"));
	public static final ArrayList<String> INTERRUPT_BLOCKS =
			new ArrayList<>(Arrays.asList("swSmi", "hwSmi", "child"));

	/**
	 * This constructor stores basic data about current program and file
	 * and analyzes this data to create a structure of functions and
	 * protocols that are related with each other
	 *
	 * @param path       the path of efi file in Ghidra project
	 * @param name       name of efi file. Must have extension .efi.
	 */
	public ProgramMetaData(String path, String name, Program program) {
		this.name = name;
		this.path = path;
		readMemoryBlock(program);
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
	 * Read {@link MemoryBlock} from specified program
	 * UEFI_BLOCKS consists available blocks for read
	 *
	 * @param program program for read Memory Blocks
	 * @return HashMap of found function and list of it's protocols
	 */
	public void readMemoryBlock(Program program) {
		EfiEntry entry;
		JSONObject obj;
		byte[] raw;
		Memory memory;
		MemoryBlock memoryBlock;

		memory = program.getMemory();
		memoryBlock = memory.getBlock(METABLOCK_NAME);
		if (memoryBlock != null) {
			try {
				raw = new byte[(int) memoryBlock.getSize()];
				memoryBlock.getBytes(memoryBlock.getStart(), raw);
				obj = new JSONObject(new String(raw, StandardCharsets.UTF_8));
				for (String protocol : UEFI_BLOCKS) {
					entry = new EfiEntry(protocol, "Function");
					entry.addReferences(parseBlock(obj.getJSONObject(protocol), entry));
					functions.add(entry);
				}
			} catch (MemoryAccessException e) {
				Msg.debug(program, "[-] No such block in program " + program.getName());
			}
		}
	}

	public static ArrayList<EfiEntry> parseBlock(JSONObject obj, EfiEntry protocol) {
		ArrayList<EfiEntry> protocols;
		String address;
		JSONObject entry;

		address = "";
		protocols = new ArrayList<>();
		if (protocol.getName().equals("interrupts")) {
			for (String interruptBlock : INTERRUPT_BLOCKS) {
				for (Iterator<String> it = obj.keys(); it.hasNext(); ) {
					try {
						address = it.next();
						entry = obj.getJSONObject(address);
						protocols.add(
								new EfiEntry(
										entry.getString("function name"),
										"",
										address,
										"Protocol",
										entry.getString("function address"),
										protocol
								)
						);
					} catch (JSONException e) {
						Msg.error(ProgramMetaData.class, "[-] Can't find " + interruptBlock + " block");
					}
				}
			}
		}
		else {
			for (Iterator<String> it = obj.keys(); it.hasNext(); ) {
				try {
					address = it.next();
					entry = obj.getJSONObject(address);
					protocols.add(
							new EfiEntry(
									entry.getString("name"),
									entry.getString("guid"),
									address,
									"Protocol",
									entry.getString("function"),
									protocol
							)
					);
				} catch (JSONException e) {
					Msg.error(ProgramMetaData.class, "[-] Can't dump efi protocol from " + protocol + " block at" + address + " address");
				}
			}
		}
		return (protocols);
	}

	public EfiEntry findProtocol(String name) {
		if (name == null)
			return null;
		for (EfiEntry entry : functions) {
			for (EfiEntry ref : entry.getReferences()) {
				if (ref.getName() != null && ref.getName().equals(name))
					return ref;
				else if (ref.getGuid() != null && ref.getGuid().equals(name) && !name.equals(GUID_DEFAULT))
					return ref;
			}
		}
		return null;
	}

	/**
	 * @return String in format:
	 * filename
	 * function1:
	 * protocol address - protocol guid
	 * protocol address - protocol guid
	 * ...
	 * ...
	 * functionN
	 */
	@Override
	public String toString() {
		StringBuilder str;

		str = new StringBuilder();
		str.append(this.name).append("\n");
		for (EfiEntry entry : functions) {
			str.append("\t").append(entry.getName()).append("\n");
			for (EfiEntry reference : entry.getReferences()) {
				str.append("\t\t").append(reference.getName()).append(" - ");
				str.append(reference.getFuncAddress()).append("\n");
			}
		}
		return str.toString();
	}
}