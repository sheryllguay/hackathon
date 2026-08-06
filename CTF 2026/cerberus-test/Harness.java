import com.ucsi.cerberus.model.*;
import com.ucsi.cerberus.service.*;
import com.ucsi.cerberus.enrich.*;
import java.nio.file.*;
import java.util.*;

public class Harness {
    public static void main(String[] args) throws Exception {
        ReportStore store = new ReportStore();
        ReportImportService imp = new ReportImportService(store);
        String json = new String(Files.readAllBytes(Paths.get(args[0])));
        try {
            ReportImportService.ImportResult r = imp.importBundle(json);
            System.out.println("imported=" + r.getImported());
            System.out.println("enrichment=" + r.getEnrichment());
        } catch (Exception e) {
            System.out.println("EXC: " + e.getMessage());
            e.printStackTrace();
        }
        // Dump enrichment object contents for debug
        System.out.println("---- store keys ----");
        for (String k : new ArrayList<String>()){ }
    }
}