package com.ucsi.cerberus.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.ucsi.cerberus.enrich.EnrichmentTask;
import com.ucsi.cerberus.model.AssetInventory;
import com.ucsi.cerberus.model.IncidentReport;
import com.ucsi.cerberus.model.Report;
import com.ucsi.cerberus.model.ReportBundle;
import com.ucsi.cerberus.model.ReportMetadata;
import com.ucsi.cerberus.model.ThreatIndicator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Deserializes uploaded report bundles into their object model.
 *
 * <p>Uses jackson-databind with polymorphic typing constrained by a
 * {@link PolymorphicTypeValidator}. The validator is configured so that only
 * the concrete report types and standard {@code java.util} containers may be
 * resolved from a type id present in an uploaded bundle. Unrecognized types are
 * rejected and the importer reports the set of accepted report types.
 */
public class ReportImportService {

    /** The concrete report types accepted during import. */
    private static final List<Class<? extends Report>> ALLOWED_REPORT_TYPES =
            Collections.unmodifiableList(Arrays.asList(
                    IncidentReport.class,
                    AssetInventory.class,
                    ThreatIndicator.class,
                    ReportMetadata.class));

    private final ObjectMapper mapper;
    private final ReportStore store;

    public ReportImportService(ReportStore store) {
        this.store = store;
        this.mapper = buildMapper();
    }

    /**
     * Builds the polymorphic ObjectMapper with a type-validator allow-list: the
     * report subtypes plus standard {@code java.util} containers, so legitimate
     * bundles can carry list/map enrichment context.
     */
    private ObjectMapper buildMapper() {
        BasicPolymorphicTypeValidator.Builder ptvBuilder =
                BasicPolymorphicTypeValidator.builder()
                        // Allow standard JDK collections as enrichment containers.
                        .allowIfSubType("java.util.");
        // Allow only the concrete report classes as polymorphic report subtypes.
        for (Class<? extends Report> t : ALLOWED_REPORT_TYPES) {
            ptvBuilder = ptvBuilder.allowIfSubType(t);
        }
        PolymorphicTypeValidator ptv = ptvBuilder.build();

        ObjectMapper m = new ObjectMapper();
        m.setPolymorphicTypeValidator(ptv);
        return m;
    }

    /** Imports a serialized report bundle. */
    public ImportResult importBundle(String bundleJson) throws ImportException {
        if (bundleJson == null || bundleJson.trim().isEmpty()) {
            throw new ImportException("Empty report bundle.", false);
        }
        try {
            // Deserialize the uploaded bundle into its object model.
            ReportBundle bundle = mapper.readValue(bundleJson, ReportBundle.class);

            int count = 0;
            if (bundle.getReports() != null) {
                for (Report r : bundle.getReports()) {
                    store.save(r);
                    count++;
                }
            }
            // Include any output captured from enrichment tasks in the result.
            List<String> enrichment = collectEnrichmentOutput(bundle.getEnrichment());
            return new ImportResult(count, enrichment);
        } catch (Exception ex) {
            if (isDisallowedTypeError(ex)) {
                throw new ImportException(disallowedTypeMessage(), true);
            }
            throw new ImportException("Malformed report bundle: unable to parse.", false);
        }
    }

    /** Pulls captured output from any EnrichmentTask(s) in the enrichment context. */
    @SuppressWarnings("unchecked")
    private List<String> collectEnrichmentOutput(Object enrichment) {
        List<String> out = new ArrayList<>();
        if (enrichment == null) {
            return out;
        }
        Collection<Object> items;
        if (enrichment instanceof Collection) {
            items = (Collection<Object>) enrichment;
        } else {
            items = Collections.singletonList(enrichment);
        }
        for (Object o : items) {
            if (o instanceof EnrichmentTask) {
                String s = ((EnrichmentTask) o).getOutput();
                if (s != null && !s.isEmpty()) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    private boolean isDisallowedTypeError(Exception ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            String msg = t.getMessage();
            if (msg != null) {
                String lower = msg.toLowerCase();
                if (lower.contains("polymorphictypevalidator")
                        || lower.contains("not allow")
                        || lower.contains("denied resolution")
                        || lower.contains("invalid type id")
                        || lower.contains("could not resolve type id")) {
                    return true;
                }
            }
        }
        return false;
    }

    private String disallowedTypeMessage() {
        String allowed = ALLOWED_REPORT_TYPES.stream()
                .map(Class::getName)
                .collect(Collectors.joining(", "));
        return "Import rejected: report type not in the accepted set. "
                + "Accepted report types: [" + allowed + "]";
    }

    /** Outcome of a successful import: the count imported and any enrichment output. */
    public static class ImportResult {
        private final int imported;
        private final List<String> enrichment;

        public ImportResult(int imported, List<String> enrichment) {
            this.imported = imported;
            this.enrichment = enrichment;
        }

        public int getImported() {
            return imported;
        }

        public List<String> getEnrichment() {
            return enrichment;
        }
    }

    /** Import failure carrying a client-safe error message. */
    public static class ImportException extends Exception {
        private final boolean whitelistEvidence;

        public ImportException(String message, boolean whitelistEvidence) {
            super(message);
            this.whitelistEvidence = whitelistEvidence;
        }

        public boolean isWhitelistEvidence() {
            return whitelistEvidence;
        }
    }
}
