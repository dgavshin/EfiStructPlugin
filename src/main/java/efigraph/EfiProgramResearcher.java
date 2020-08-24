package efigraph;//TODO write a description for this script
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
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class EfiProgramResearcher {

	public EfiEntry 	target;
	private ProjectData pd;

	public HashMap<String, EfiEntry> locateEntries = new HashMap<>();
	public HashMap<String, EfiEntry> installEntries = new HashMap<>();

	public static String LOCATE_PROTOCOL = "locateProtocol";
	public static String INSTALL_PROTOCOL = "installProtocol";

	public EfiProgramResearcher(EfiEntry target)
	{
		this.target = target;
		try {
			if (this.target != null) {
				pd = EfiGraphProvider.tool.getProject().getProjectData();
				handleFilesRecursively(EfiGraphProvider.tool.getProject().getProjectData().getRootFolder());
			}
			else
				Msg.warn(this, "[-] Target is null");
		} catch (Exception e)
		{
			Msg.warn(this, "[-] Can't create EfiProgramResearcher instance: " + e.getMessage());
		}
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
			return (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		} catch (VersionException | IOException | CancelledException e) {
			Msg.error(this, "[-] Could not get domain object from domain file\n" + e.getMessage());
			return (null);
		}
	}

	public void handleFilesRecursively(DomainFolder folder)
	{
		Program				program;
		String				pathname;

		for (DomainFile file : folder.getFiles()) {
			pathname = file.getPathname();
			if (!pathname.matches(".+?\\.efi"))
				continue;
			program = getProgramFromPath(pathname);
			if (program == null)
				continue;
			analyzeReferences(program);
		}
		for (DomainFolder subFolder : folder.getFolders())
			handleFilesRecursively(subFolder);
	}

	public void analyzeReferences(Program program) {
		EfiCache cache;

		try {
			cache = new EfiCache(program, EfiGraphProvider.tool);

			for (EfiEntry function : cache.PMD.getFunctions()) {
				if (!(function.getName().equals(LOCATE_PROTOCOL) && EfiGraphProvider.INSTALL_ENTRY) &&
						!(function.getName().equals(INSTALL_PROTOCOL) && EfiGraphProvider.LOCATE_ENTRY))
					continue;
				for (EfiEntry entry : function.getReferences()) {
					if (entry.equals(target)) {
						if (function.getName().equals(LOCATE_PROTOCOL))
							locateEntries.put(program.getName(), entry);
						else
							installEntries.put(program.getName(), entry);
					}
				}
			}
		} catch (Exception e) {
			Msg.warn(this, "[-] Create or get cached instance of ProgramMetaData class failed: " + e.getMessage());
		}
	}
}

