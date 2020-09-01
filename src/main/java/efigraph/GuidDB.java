package efigraph;

import ghidra.framework.Application;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import static efigraph.EfiGraphProvider.plugin;

/**
 *
 */
public class GuidDB implements Serializable {

	public static String GUID_DB_NAME = "guids-db.ini";
	public static String GUID_DEFAULT = "ffffffff-ffff-ffff-ffff-ffffffffffff";
	public static String GUID_NAME_REGEX = "^[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}$";
	public static String PROTOCOL_NAME_REGEX = "^[g\\dA-Z_]+_(GUID|PROTOCOL).?$";

	private final HashMap<String, String> guids = parseGuidsBase();

	public String getProtocol(String guid)
	{
		String entry = null;

		if (this.guids != null)
			entry = this.guids.get(guid);
		return entry == null ? guid : entry;
	}

	public static String getEntryType(String entry)
	{
		if (entry != null) {
			if (entry.toLowerCase().matches(GUID_NAME_REGEX))
				return "guid";
			else if (entry.matches(PROTOCOL_NAME_REGEX))
				return "protocol";
		}
		return "unknown";
	}

	private HashMap<String, String> parseGuidsBase() {
		HashMap<String, String> guids = new HashMap<>();
		String guidSrt;

		try {
			Path guidBasePath = Paths
					.get(Application.getModuleDataFile(plugin.getName(), "guids-db.ini").getAbsolutePath());
			guidSrt = Files.readString(guidBasePath);
		} catch (IOException e) {
			Msg.error(EfiCache.class, "[-] Problem with path to guid-db file\n" + e.getMessage());
			return null;
		}
		String delimits = "[ {}=\n\r\t]+";

		String[] tempGuids = guidSrt.split(delimits);
		for (int j = 0; j < tempGuids.length; j += 2) {
			if (tempGuids[j].compareToIgnoreCase("[EDK]") == 0 || tempGuids[j].compareToIgnoreCase("[AMI]") == 0
					|| tempGuids[j].compareToIgnoreCase("[Apple]") == 0
					|| tempGuids[j].compareToIgnoreCase("[INTEL]") == 0
					|| tempGuids[j].compareToIgnoreCase("[NEW]") == 0
					|| tempGuids[j].compareToIgnoreCase("[INSYDE]") == 0
					|| tempGuids[j].compareToIgnoreCase("[ACER]") == 0
					|| tempGuids[j].compareToIgnoreCase("[AMI+]") == 0
					|| tempGuids[j].compareToIgnoreCase("[PHOENIX]") == 0) {
				j++;
			}
			guids.put(tempGuids[j + 1], tempGuids[j]);
		}
		return guids;
	}
}
