package efigraph;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import java.io.Serializable;
import java.util.ArrayList;

import static efigraph.EfiGraphProvider.USER_SYMBOLS;
import static efigraph.EfiGraphProvider.guidDB;
import static efigraph.GuidDB.getEntryType;

public class EfiEntry implements Serializable {

	private String name;
	private final String funcAddress;

	private EfiEntry parentProtocol;
	private String service;
//    private Symbol          symbol;

	private final ArrayList<EfiEntry> references = new ArrayList<>();

	public Address getAddress(Program program) {
		if (program == null)
			return null;
		try {
			return program.getAddressFactory().getAddress(this.funcAddress);
		} catch (NullPointerException e)
		{
			Msg.warn(this, "[-] Can't find specified address: " + funcAddress + "\n" + e.getMessage());
			return null;
		}
	}

	public EfiEntry(String name, String funcAddress, EfiEntry parentProtocol) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		this.funcAddress = funcAddress;
		this.parentProtocol = parentProtocol;
	}

	public EfiEntry(String name, String funcAddress) {

		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		this.funcAddress = funcAddress;
		this.parentProtocol = null;
	}

	public EfiEntry(String name) {
		if (getEntryType(name).equals("guid"))
			this.name = guidDB.getProtocol(name);
		this.parentProtocol = null;
		this.funcAddress = null;
	}

	public void setParentProtocol(EfiEntry parentProtocol) {
		this.parentProtocol = parentProtocol;
	}

	public EfiEntry getParentProtocol() {
		return parentProtocol;
	}

	public String getName() {
		return name;
	}

	public String getFuncAddress(Program program) {
		if (program == null)
			return getKey();
		else
		{
			Address address = getAddress(program);
			if (address == null)
				return null;
			return address.toString();
		}
	}

	public void addReferences(ArrayList<EfiEntry> protocols) {
		references.addAll(protocols);
		protocols.forEach(e -> e.setParentProtocol(this));
	}

	public void addReference(EfiEntry protocol) {
		references.add(protocol);
		protocol.setParentProtocol(this);
	}

	public ArrayList<EfiEntry> getReferences() {
		return references;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String getService() {
		return service;
	}

	public Symbol getSymbol() {
		return (USER_SYMBOLS == null ? null : USER_SYMBOLS.get(name));
	}

	public String getKey()
	{
		Symbol symbol = getSymbol();
		if (symbol == null) {
			Msg.warn(this, "[-] Can't find symbol by name: " + this.name);
			return this.name;
		}
		return symbol.getAddress() + " o " + symbol.getID();
	}
}
