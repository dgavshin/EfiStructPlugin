package efigraph;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import static efigraph.EfiGraphProvider.*;
import static efigraph.GuidDB.GUID_DB_NAME;
import static efigraph.ProgramMetaData.readMemoryBlocks;

public class EfiCache {

    public static final String CACHE_FOLDER_NAME = "efigraph_cached";
    public static Path CACHE_FOLDER;
    public Program program;
    public PluginTool tool;

    public EfiCache(Program program, PluginTool tool) {

        this.program = program;
        this.tool = tool;

        getUserSymbols().forEach(e -> USER_SYMBOLS.put(e.getName(), e));
        initCache();
    }

    boolean isCached(String filename) {
        return (Files.exists(Paths.get(CACHE_FOLDER + "\\" + filename + ".ser")));
    }

    Object getCachedFile(String filename) {
        FileInputStream fis;
        ObjectInputStream ois;
        Object pmd;

        pmd = null;
        try {
            fis = new FileInputStream(CACHE_FOLDER + "\\" + filename + ".ser");
            ois = new ObjectInputStream(fis);
            pmd = ois.readObject();
            ois.close();
            fis.close();
            Msg.info(this, "[+] Get file from cache: " + CACHE_FOLDER + "\\" + filename + ".ser");
        } catch (Exception e) {
            Msg.error(this, "[-] Can't deserialize class\n" + e.getMessage());
        }
        return (pmd);
    }

    void cacheFile(Object obj, String filename) {
        FileOutputStream fos;
        ObjectOutputStream oos;

        try {
            fos = new FileOutputStream(CACHE_FOLDER + "\\" + filename + ".ser");
            oos = new ObjectOutputStream(fos);
            oos.writeObject(obj);
            oos.close();
            fos.close();
            Msg.info(this, "[+] File cached: " + CACHE_FOLDER + "\\" + filename + ".ser");
        } catch (Exception e) {
            Msg.error(this, "[-] Can't serialize class\n" + e.getMessage());
        }
    }

    void initCache() {
        String pathname;
        String name;

        CACHE_FOLDER = Paths.get(EfiGraphPlugin.PROJECT_PATH + "\\" + CACHE_FOLDER_NAME);
        if (!Files.exists(CACHE_FOLDER)) {
            try {
                Files.createDirectory(CACHE_FOLDER);
                Msg.info(this, "[+] Cache folder created: " + CACHE_FOLDER);
            } catch (IOException e) {
                Msg.warn(this, e.getMessage());
            }
        }

        guidDB = (GuidDB) getCachedFile(GUID_DB_NAME);
        if (guidDB == null)
        {
            guidDB = new GuidDB();
            cacheFile(guidDB, GUID_DB_NAME);
        }

        PMD = (ProgramMetaData) getCachedFile(program.getName());
        if (PMD == null) {
            pathname = program.getDomainFile().getPathname();
            name = program.getName();
            PMD = new ProgramMetaData(pathname, name, readMemoryBlocks(program));
            cacheFile(PMD, PMD.getName());
        }
    }

    public ArrayList<Symbol> getUserSymbols() {
        ArrayList<Symbol> symbols = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true))
            if (symbol.getSource() == SourceType.USER_DEFINED)
                symbols.add(symbol);
        return (symbols);
    }

}
