import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.jsontype.*;
import com.fasterxml.jackson.databind.cfg.MapperConfig;;
import com.ucsi.cerberus.model.*;

public class ProbeValidator {
    static PolymorphicTypeValidator build() {
        BasicPolymorphicTypeValidator.Builder b =
            BasicPolymorphicTypeValidator.builder().allowIfSubType("java.util.");
        for (Class<? extends Report> t : java.util.Arrays.asList(
                IncidentReport.class, AssetInventory.class,
                ThreatIndicator.class, ReportMetadata.class)) {
            b = b.allowIfSubType(t);
        }
        return b.build();
    }
    public static void main(String[] args) throws Exception {
        PolymorphicTypeValidator ptv = build();
        ObjectMapper m = new ObjectMapper();
        MapperConfig<?> ctxt = m.getSerializationConfig();
        String[] names = {
            "com.ucsi.cerberus.enrich.EnrichmentTask",
            "com.ucsi.cerberus.enrich.CommandRunner",
            "com.ucsi.cerberus.model.Report",
            "java.util.ArrayList",
            "java.util.concurrent.ConcurrentHashMap",
            "java.util.HashMap",
            "java.lang.Object",
            "java.lang.String",
            "java.util.concurrent.atomic.AtomicReference",
            "com.fasterxml.jackson.databind.node.ObjectNode"
        };
        for (String n : names) {
            Class<?> c = null;
            try { c = Class.forName(n); } catch (Exception e){ System.out.println(n+" -> (no class) "+e.getMessage()); continue; }
            JavaType baseType = m.constructType(Object.class);
            JavaType subType = m.constructType(c);
            PolymorphicTypeValidator.Validity v1 = ptv.validateBaseType(ctxt, baseType);
            PolymorphicTypeValidator.Validity v2 = ptv.validateSubType(ctxt, baseType, subType);
            System.out.println(n + " : base=" + v1 + " sub=" + v2);
        }
    }
}