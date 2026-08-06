import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.jsontype.*;
import com.ucsi.cerberus.model.*;
import com.ucsi.cerberus.enrich.*;
import java.nio.file.*;
import java.util.*;

public class Harness2 {
    static ObjectMapper build() {
        BasicPolymorphicTypeValidator.Builder b =
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("java.util.");
        for (Class<? extends Report> t : Arrays.asList(
                IncidentReport.class, AssetInventory.class,
                ThreatIndicator.class, ReportMetadata.class)) {
            b = b.allowIfSubType(t);
        }
        PolymorphicTypeValidator ptv = b.build();
        ObjectMapper m = new ObjectMapper();
        m.setPolymorphicTypeValidator(ptv);
        return m;
    }
    public static void main(String[] args) throws Exception {
        ObjectMapper m = build();
        String json = new String(Files.readAllBytes(Paths.get(args[0])));
        try {
            ReportBundle bundle = m.readValue(json, ReportBundle.class);
            Object en = bundle.getEnrichment();
            System.out.println("enrichment class = " + (en==null?null:en.getClass().getName()));
            System.out.println("enrichment = " + en);
            if (en instanceof Collection) {
                int i=0;
                for (Object o : (Collection<?>) en) {
                    System.out.println("  elem["+i+"] class="+o.getClass().getName()+" val="+o);
                    i++;
                }
            }
        } catch (Exception e) {
            System.out.println("EXC: " + e);
            Throwable c = e; while (c!=null){ System.out.println("  cause: "+c.getClass().getName()+": "+c.getMessage()); c=c.getCause(); }
        }
    }
}