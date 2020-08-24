package efigraph;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import java.io.Serializable;
import java.util.ArrayList;

import static efigraph.EfiGraphProvider.USER_SYMBOLS;
import static efigraph.EfiCache.guidDB;
import static efigraph.GuidDB.getEntryType;

public class EfiEntry implements Serializable {

	private String 			name;
	private String			guid;
	private final String 	funcAddress;

	private EfiEntry 		parentEntry;
	//    private Symbol          symbol;

	private final ArrayList<EfiEntry> references = new ArrayList<>();

	/**
	 * The key unit in working with graph vertices, analyzing programs,
	 * caching. Intended for wrapping efi protocols, functions and global services.
	 * @param name entry unique name
	 * @param funcAddress address of function where is entry located
	 * @param parentEntry parent entry
	 */
	public EfiEntry(String name, String funcAddress, EfiEntry parentEntry) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		else
			this.name = name;
		this.guid = name;
		this.funcAddress = funcAddress;
		this.parentEntry = parentEntry;
	}

	/**
	 * The key unit in working with graph vertices, analyzing programs,
	 * caching. Intended for wrapping efi protocols, functions and global services.
	 * @param name entry unique name
	 */
	public EfiEntry(String name) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		else
			this.name = name;
		this.guid = name;
		this.parentEntry = null;
		this.funcAddress = null;
	}

	/**
	 * Compares two entries by their guids and names.
	 * @param obj object for comparing
	 * @return True if guids and name equals, otherwise False
	 */
	@Override
	public boolean equals(Object obj) {
		try {
			if (obj.getClass() == this.getClass()) {
				EfiEntry entry = (EfiEntry) obj;
				if (this.getName().equals(entry.getName()) && this.getGuid().equals(entry.getGuid()))
					return true;
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	/**
	 * Globally unique identifier (GUID) is a 128-bit number
	 * used to identify information in computer systems
	 *
	 * @return unique protocol GUID
	 */
	public String getGuid() {
		return guid;
	}

	/**
	 *
	 * @param parentEntry a unit that has some parent relation to the unit
	 *                          of the class being called. (For example, service
	 *                          gBS call locate protocol, for locate protocol entry
	 *                          gBS is parent)
	 */
	public void setParentEntry(EfiEntry parentEntry) {
		this.parentEntry = parentEntry;
	}

	/**
	 * @return EfiEntry instance that has some parent relation with this class,
	 * null if class does not have a parent ({@link EfiEntry#parentEntry} is null).
	 */
	public EfiEntry getParentProtocol() {
		return parentEntry;
	}

	/**
	 * @return the name of this entry
	 */
	public String getName() {
		return name;
	}

	/**
	 * EfiEntry implements {@link Serializable} so {@link Program} can't
	 * store in this class, each time this method is called you must explicitly
	 * specify the program where the function address is being searched.
	 * @param program where will be searching {@link Address}
	 * @return {@link Address} from funcAddress string,
	 *		   {@link #getKey()} if program is null,
	 *		   null if no such address.
	 */
	public String getFuncAddress(Program program) {
		if (program == null)
			return getKey();
		else
		{
			try {
				Address address = program.getAddressFactory().getAddress(this.funcAddress);
				Msg.info(this, "[+] Founded address " + address.toString());
				return address.toString();
			} catch (NullPointerException e) {
				Msg.warn(this, "[-] Can't find " + funcAddress + " address\n" + e.getMessage());
				return null;
			}
		}
	}

	/**
	 * Creates some kind of child link between entry and class being called.
	 * @param entry child entry
	 * @param fromAnotherFile if true, for entry will not be set parent,
	 *                        otherwise as parent will be set this class.
	 */
	public void addReference(EfiEntry entry, boolean fromAnotherFile) {
		references.add(entry);
		if (!fromAnotherFile)
			entry.setParentEntry(this);
	}

	/**
	 * @return as list all child {@link EfiEntry} links of this class
	 */
	public ArrayList<EfiEntry> getReferences() {
		return references;
	}

	/**
	 * This method uses global HashMap {@link EfiGraphProvider#USER_SYMBOLS}
	 * which contains users symbols. User symbols are symbols with flag
	 * {@link ghidra.program.model.symbol.SourceType#USER_DEFINED} in Symbol Table.
	 * @return symbol by entry {@link EfiEntry#name}.
	 */
	public Symbol getSymbol() {
		return (USER_SYMBOLS == null ? null : USER_SYMBOLS.get(name));
	}

	/**
	 *
	 * @return
	 */
	public String getKey()
	{
		Symbol symbol = getSymbol();
		if (symbol == null) {
			Msg.warn(this, "[-] Can't find symbol by name: " + this.name);
			return this.funcAddress;
		}
		Msg.info(this, "[+] Founded symbol by name: " + this.name);
		return symbol.getAddress().toString();
	}
}
