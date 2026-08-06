package com.ucsi.cerberus.model;

/**
 * Report type: bundle-level metadata (exporting system, schema version).
 */
public class ReportMetadata extends Report {

    private String exportedBy;
    private String schemaVersion;

    public String getExportedBy() {
        return exportedBy;
    }

    public void setExportedBy(String exportedBy) {
        this.exportedBy = exportedBy;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    @Override
    public String kind() {
        return "metadata";
    }
}
