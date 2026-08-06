package com.ucsi.cerberus.model;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * Top-level container deserialized from an uploaded report bundle.
 *
 * <p>A bundle carries two payloads:
 *
 * <ol>
 *   <li>{@code reports} — a {@code List<Report>} of the concrete report kinds
 *       included in the export.</li>
 *
 *   <li>{@code enrichment} — an optional free-form "enrichment context" object
 *       attached by the exporting system.</li>
 * </ol>
 */
public class ReportBundle {

    private String bundleName;
    private String source;

    /** The reports contained in this bundle. */
    private List<Report> reports = new ArrayList<>();

    /**
     * Free-form "enrichment context" attached by the exporting system.
     *
     * <p>Declared as {@code Object} with class-name polymorphic typing so any
     * enrichment context type the exporting system used can be reconstructed on
     * import (see {@code ReportImportService} for type resolution).
     */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.WRAPPER_ARRAY)
    private Object enrichment;

    public String getBundleName() {
        return bundleName;
    }

    public void setBundleName(String bundleName) {
        this.bundleName = bundleName;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public List<Report> getReports() {
        return reports;
    }

    public void setReports(List<Report> reports) {
        this.reports = reports;
    }

    public Object getEnrichment() {
        return enrichment;
    }

    public void setEnrichment(Object enrichment) {
        this.enrichment = enrichment;
    }
}
