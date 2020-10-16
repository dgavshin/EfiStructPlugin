package efistruct;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;


public class EfiProgramResearcher {

	public EfiEntry 	target;
	public static ProjectData pd = EfiGraphProvider.tool.getProject().getProjectData();

	public Set<ProgramMetaData> founded_programs = new HashSet<>();

	public static String LOCATE_PROTOCOL = "locate protocol";
	public static String INSTALL_PROTOCOL = "install protocol";

	public EfiProgramResearcher(EfiEntry target)
	{
		this.target = target;
		try {
			if (this.target != null)
				handleFilesRecursively(EfiGraphProvider.tool.getProject().getProjectData().getRootFolder());
			else
				Msg.warn(this, "[-] Target is null");
		} catch (Exception e) {
			Msg.warn(this, "[-] Can't create EfiProgramResearcher instance: " + e.getMessage());
		}
	}

	public void handleFilesRecursively(DomainFolder folder)
	{
		String				pathname;

		for (DomainFile file : folder.getFiles()) {
			pathname = file.getPathname();
			if (!pathname.matches(".+?\\.efi"))
				continue;
			analyzeReferences(pathname, file.getName());
		}
		for (DomainFolder subFolder : folder.getFolders())
			handleFilesRecursively(subFolder);
	}

	public void analyzeReferences(String pathname, String programName) {
		EfiCache cache;

		try {
			cache = new EfiCache(pathname, programName, false);

			for (EfiEntry function : cache.PMD.getFunctions()) {
				if (function.getName().equals(target.getParent().getName())
						|| (!function.getName().equals(LOCATE_PROTOCOL)
						&& !function.getName().equals(INSTALL_PROTOCOL)))
					continue;
				function.getReferences().forEach(e -> {
					if (e.equals(target))
						founded_programs.add(cache.PMD);
				});
			}
		} catch (Exception e) {
			Msg.warn(this, "[-] Create or get cached instance of ProgramMetaData class failed: " + e.getMessage());
		}
	}

	public static Program getProgramFromPath(String programPath) {
		DomainFile df;

		df = pd.getFile(programPath);
		if (df == null) {
			Msg.error(EfiProgramResearcher.class, "[-] Could not find program by specified path: " + programPath);
			return (null);
		}
		try {
			return (Program) df.getDomainObject(EfiProgramResearcher.class, false, false, TaskMonitor.DUMMY);
		} catch (VersionException | IOException | CancelledException e) {
			Msg.error(EfiProgramResearcher.class, "[-] Could not get domain object from domain file\n" + e.getMessage());
			return (null);
		}
	}
}

