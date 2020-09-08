package efigraph;

import ghidra.graph.visualization.Colors;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.Msg;
import org.apache.commons.collections4.map.CompositeMap;
import org.apache.commons.lang.ObjectUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.HashMap;

import static efigraph.EfiCache.guidDB;
import static efigraph.EfiGraphProvider.*;
import static efigraph.GuidDB.getEntryType;

public class EfiEntry implements Serializable {

	private final String 	name;
	private final String	guid;
	private final String	type;
	private final String 	funcAddress;
	private EfiEntry 		parentEntry;

	private final ArrayList<EfiEntry> references = new ArrayList<>();

	/**
	 * The key unit in working with graph vertices, analyzing programs,
	 * caching. Intended for wrapping efi protocols, functions and global services.
	 * @param name entry unique name
	 * @param funcAddress address of function where is entry located
	 * @param parentEntry parent entry
	 */
	public EfiEntry(String name, String funcAddress, EfiEntry parentEntry, String type) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		else
			this.name = name;
		this.guid = name;
		this.funcAddress = funcAddress;
		this.parentEntry = parentEntry;
		this.type = type;
	}

	/**
	 * The key unit in working with graph vertices, analyzing programs,
	 * caching. Intended for wrapping efi protocols, functions and global services.
	 * @param name entry unique name
	 */
	public EfiEntry(String name, String type) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		else
			this.name = name;
		this.guid = name;
		this.type = type;
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

	public String getFuncAddress() {
		return funcAddress;
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
	 * @return type of the Entry. Protocol, function or global
	 */
	public String getType() {
		return type;
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
		return (USER_SYMBOLS == null ? null : USER_SYMBOLS.get(this.name));
	}

	public String getId(Program program) {
		Address address;
		Symbol symbol;

		if (program != null)
		{
			if (this.name == null && funcAddress != null) {
				address = program.getAddressFactory().getAddress(funcAddress);
				if (address != null)
					return address.toString();
			}
			else if (this.name != null && funcAddress == null)
			{
				symbol = getSymbol();
				if (symbol != null)
					return symbol.getAddress().toString();
			}
			else
				return this.name;
		}
		return this.name + ":" + this.funcAddress;
	}

	public AttributedVertex createVertex(String suffix, Program program, HashMap<String, HashMap<String, String>> attributes)
	{
		AttributedVertex vertex = new AttributedVertex(suffix + getId(program), suffix + this.getName());
		vertex.putAttributes(attributes.get(this.type));
		return vertex;
	}
}
