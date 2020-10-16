package efistruct;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.Msg;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

import static efistruct.EfiGraphPlugin.USER_SYMBOLS;
import static efistruct.EfiGraphProvider.program;

public class EfiEntry implements Serializable {

	private final String 	name;
	private final String	guid;
	private final String	type;
	private final String	address;
	private final String 	funcAddress;

	private final ArrayList<EfiEntry> references = new ArrayList<>();
	private final EfiEntry parent;

	/**
	 * The key unit in working with graph vertices, analyzing programs,
	 * caching. Intended for wrapping efi protocols, functions and global services.
	 * @param name entry unique name
	 */
	public EfiEntry(String name, String type)
	{
		this.name = name;
		this.guid = "";
		this.funcAddress = "";
		this.type = type;
		this.address = "";
		this.parent = null;
	}

	public EfiEntry(String name, String guid, String address, String type, String funcAddress, EfiEntry parent)
	{
		this.parent = parent;
		this.name = name;
		this.guid = guid;
		this.funcAddress = funcAddress;
		this.type = type;
		this.address = address;
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

	@Override
	public int hashCode() {
		return Objects.hash(name, guid, type, address, funcAddress);
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
	 * @return the name of this entry
	 */
	public String getName() {
		return name;
	}

	public String getFuncAddress() {
		return funcAddress;
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
	public void	addReferences(ArrayList<EfiEntry> list)
	{
		references.addAll(list);
	}
	public void addReference(EfiEntry entry) {
		references.add(entry);
	}

	/**
	 * This method uses global HashMap
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
			if (this.address != null) {
				address = program.getAddressFactory().getAddress(this.address);
				if (address != null)
					return address.toString();
			}
			else if (this.funcAddress != null)
			{
				address = program.getAddressFactory().getAddress(this.funcAddress);
				if (address != null)
					return address.toString();
			}
			else if (this.name != null)
			{
				symbol = getSymbol();
				if (symbol != null)
					return symbol.getAddress().toString();
				else
					return name;
			}
		}
		return this.name + ":" + this.funcAddress;
	}

	public Address getAddress()
	{
		try {
			return (program.getAddressFactory().getAddress(this.address));
		} catch (Exception e)
		{
			Msg.error(this, "Can't retrieve address from address string " + this.address);
			return (null);
		}
	}

	public Function getFunction()
	{
		try {
			Address address = program.getAddressFactory().getAddress(funcAddress);
			return program.getFunctionManager().getFunctionAt(address);
		} catch (NullPointerException e)
		{
			Msg.error(EfiEntry.class, "Can't find function by specified address - " + this.funcAddress);
			return null;
		}
	}

	public EfiEntry getParent()
	{
		return this.parent;
	}

	public AttributedVertex createVertex(String suffix, Program program, HashMap<String, HashMap<String, String>> attributes)
	{
		AttributedVertex vertex = new AttributedVertex(suffix + getId(program), suffix + this.getName());
		vertex.putAttributes(attributes.get(this.type));
		return vertex;
	}
}
