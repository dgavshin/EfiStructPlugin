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

import static efigraph.GuidDB.GUID_DB_NAME;
import static efigraph.ProgramMetaData.readMemoryBlocks;

/**
 * EfiCache class manages caching, retrieving from cache, and creating main instances
 * for faster plugin performance. If {@link #CACHE_FOLDER} doesn't exists, EfiCache will
 * create this folder and then will save there all cached instance.
 */
public class EfiCache {

    public static final String CACHE_FOLDER_NAME = "efigraph_cached";
    public Path CACHE_FOLDER;
    public Program program;
    public PluginTool tool;
    public static GuidDB guidDB;
    public ProgramMetaData PMD;

    /**
     * This constructor launch method {@link #initCache()}
     *
     * @param program that will produce cache
     * @param tool main plugin tool
     */
    public EfiCache(Program program, PluginTool tool) {

        this.program = program;
        this.tool = tool;

        initCache();
    }

    /**
     * Init cache for {@link GuidDB} and {@link ProgramMetaData} if their instances
     * are serialized in {@link #CACHE_FOLDER}, if not, it will create them and cache them.
     *
     * For serializing all instances implements {@link Serializable}.
     * {@link ObjectInputStream} and {@link ObjectOutputStream} used for
     * deserializing and serializing respectively.
     */
    void initCache() {
        String pathname;
        String name;

        this.CACHE_FOLDER = Paths.get(EfiGraphPlugin.PROJECT_PATH + "\\" + CACHE_FOLDER_NAME);
        if (!Files.exists(this.CACHE_FOLDER)) {
            try {
                Files.createDirectory(this.CACHE_FOLDER);
                Msg.info(this, "[+] Cache folder created: " + this.CACHE_FOLDER);
            } catch (IOException e) {
                Msg.warn(this, e.getMessage());
            }
        }

        if (guidDB == null) {
            guidDB = (GuidDB) getCachedFile(GUID_DB_NAME);
            if (guidDB == null) {
                guidDB = new GuidDB();
                cacheFile(guidDB, GUID_DB_NAME);
            }
        }

        this.PMD = (ProgramMetaData) getCachedFile(program.getName());
        if (this.PMD == null) {
            pathname = program.getDomainFile().getPathname();
            name = program.getName();
            this.PMD = new ProgramMetaData(pathname, name, readMemoryBlocks(program));
            cacheFile(this.PMD, this.PMD.getName());
        }
    }

    /**
     * Checking serialized file in {@link #CACHE_FOLDER}
     * @param filename filename to check
     * @return True if cached, otherwise False
     */
    boolean isCached(String filename) {
        return (Files.exists(Paths.get(CACHE_FOLDER + "\\" + filename + ".ser")));
    }

    /**
     * Retrieving serialized class from {@link #CACHE_FOLDER}
     * by {@link ObjectInputStream}
     * @param filename filename of retrieving class
     * @return deserialized object
     */
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
//            Msg.info(this, "[+] Get file from cache: " + CACHE_FOLDER + "\\" + filename + ".ser");
        } catch (Exception e) {
            Msg.error(this, "[-] Can't deserialize class\n" + e.getMessage());
        }
        return (pmd);
    }

    /**
     * Caching (serialize) obj regardless of whether it is cached or not
     * @param obj object to serialized
     * @param filename filename for future serialized file
     */
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

}
