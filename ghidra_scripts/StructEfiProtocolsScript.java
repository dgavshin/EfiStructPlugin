//TODO write a description for this script
//@author
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class StructEfiProtocolsScript extends GhidraScript {

	public final static ArrayList<String> uefiBlocks = new ArrayList<>(
																Arrays.asList("regInterrupt",
																			  "locateProtocol",
																			  "installProtocol",
																			  "childSmi"));
	public static final String CACHE_FOLDER_NAME = "efigraph_cached_script";
	public static Path CACHE_FOLDER;
	public static String CACHE_FOLDER_PATH;
	private final ProjectData pd = getProjectRootFolder().getProjectData();
	private ArrayList<ProgramMetaData> metaData = new ArrayList<>();

	public boolean isCached(String filename) {
		return (Files.exists(Paths.get(CACHE_FOLDER_PATH + "\\" + filename + ".ser")));
	}

	public ProgramMetaData getCachedFile(String filename)
	{
		FileInputStream 	fis;
		ObjectInputStream 	ois;
		ProgramMetaData 	pmd;

		pmd = null;
		try {
			fis = new FileInputStream(CACHE_FOLDER + "\\" + filename + ".ser");
			ois = new ObjectInputStream(fis);
			pmd = (ProgramMetaData) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException | ClassNotFoundException e) {
			Msg.error(this, "[-] Can't deserialize class\n" + e.getMessage());
		}
		return (pmd);
	}

	public void cacheFile(ProgramMetaData pmd)
	{
		FileOutputStream 	fos;
		ObjectOutputStream 	oos;

		try {
			fos = new FileOutputStream(CACHE_FOLDER + "\\" + pmd.name + ".ser");
			oos = new ObjectOutputStream(fos);
			oos.writeObject(pmd);
			oos.close();
			fos.close();
		} catch (IOException e) {
			println("no :(\n" + e.getMessage() + "\n" + e.toString());
			Msg.error(this, "[-] Can't serialize class\n" + e.getMessage());
		}
	}

	private HashMap<String, ArrayList<String>> readMemoryBlocks(Program program)
	{
		byte[]      raw;
		Memory      memory;
		MemoryBlock memoryBlock;
		HashMap<String, ArrayList<String>> blocks;

		blocks = new HashMap<>();
		memory = program.getMemory();
		for (String blockName : StructEfiProtocolsScript.uefiBlocks) {
			memoryBlock = memory.getBlock(blockName);
			if (memoryBlock != null) {
				raw = new byte[(int) memoryBlock.getSize()];
				try {
					memoryBlock.getBytes(memoryBlock.getStart(), raw);
					blocks.put(blockName, parseRawBlock(raw));
				} catch (MemoryAccessException e) {
					Msg.debug(this, "[-] No such block in program " + program.getName());
				}
			}
		}
		return (blocks);
	}


	public ArrayList<String> parseRawBlock(byte[] raw)
	{
		String data;

		data = new String(raw);
		data = data.substring(1, data.length() - 1);
		return (new ArrayList<>(Arrays.asList(data.split(", "))));
	}

	private Program getProgramFromPath(String programPath)
    {
		DomainFile df;

		df = pd.getFile(programPath);
		if (df == null) {
			Msg.error(this, "[-] Could not find program by specified path: " + programPath);
			return (null);
		}
		try {
			return (Program) df.getDomainObject(this, false, false, monitor);
		} catch (VersionException | IOException | CancelledException e) {
			Msg.error(this, "[-] Could not get domain object from domain file\n" + e.getMessage());
			return (null);
		}
	}

	public void handleFilesRecursively(DomainFolder folder)
    {
    	ProgramMetaData pmd;
		Program			program;
		String			pathname;

		for (DomainFile file : folder.getFiles())
		{
			pathname = file.getPathname();
			if (pathname.matches(".+?\\.efi"))
			{
				program = getProgramFromPath(pathname);
				if (program != null)
				{
					if (isCached(program.getName())) {
						metaData.add(getCachedFile(program.getName()));
						println("[From Cache] " + pathname);
					}
					else
					{
						pmd = new ProgramMetaData(pathname, program.getName(), readMemoryBlocks(program));
						metaData.add(pmd);
						cacheFile(pmd);
						println("[Cached!] " + pathname);
					}
				}
			}
		}
		for (DomainFolder subFolder : folder.getFolders())
			handleFilesRecursively(subFolder);
	}

	public String getProjectPath() { return (getProjectRootFolder().getProjectLocator().getProjectDir().getPath()); }

    public void run() throws Exception
    {
        DomainFolder workingFolder = askProjectFolder("Choose folder for scan");

//        double start = System.currentTimeMillis();

		CACHE_FOLDER = Paths.get(getProjectPath() + "\\" + CACHE_FOLDER_NAME);
		if (!Files.exists(CACHE_FOLDER))
			Files.createDirectory(CACHE_FOLDER);
		CACHE_FOLDER_PATH = CACHE_FOLDER.toFile().getAbsolutePath();
		handleFilesRecursively(workingFolder);

		double end = System.currentTimeMillis();
		StringBuffer str = new StringBuffer();
		for (ProgramMetaData pmd: metaData)
			str.append(pmd.toString());
		println(str.toString());
//		println("Time = " + (end - start) / 1000);
    }

	static class ProgramMetaData implements Serializable
	{
		public String   name;
		public String   path;
		public HashMap<String, ArrayList<String>> metaBlocks;

		public ProgramMetaData(String path, String name, HashMap<String, ArrayList<String>> metaBlocks)
		{
			this.name = name;
			this.path = path;
			this.metaBlocks = metaBlocks;
		}

		/*
		 ** TODO: Only in 9.2 Ghidra version
		 */
//		public String toJson()
//		{
//			return Json.toString(this);
//		}

		/*
		 ** TODO: Create format for specified graph handler
		 */
		@Override
		public String toString() {
			StringBuilder	str;
			String[]		split;

			str = new StringBuilder();
			str.append(this.name).append("\n");
			for (Map.Entry<String, ArrayList<String>> entry: this.metaBlocks.entrySet())
			{
				str.append("\t").append(entry.getKey()).append("\n");
				for (String protocol: entry.getValue())
				{
					split = protocol.split("=");
					str.append("\t\t").append(split[0]).append("\n");
				}
			}
			return str.toString();
		}
	}
}

