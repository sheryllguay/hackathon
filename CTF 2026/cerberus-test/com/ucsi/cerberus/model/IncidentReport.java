package com.ucsi.cerberus.model;

/**
 * Report type: a security incident write-up.
 *
 * <p>A plain data bean with string fields describing an incident's severity
 * and summary.
 */
public class IncidentReport extends Report {

    private String severity;
    private String summary;

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    @Override
    public String kind() {
        return "incident";
    }
}
