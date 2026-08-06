package com.ucsi.cerberus.model;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Base type for every report contained in an imported bundle.
 *
 * <p>Report bundles are polymorphic: each element of a bundle's {@code reports}
 * list is one concrete report kind, carried in the serialized bundle as a
 * class-name-tagged wrapper array, e.g.
 * {@code ["com.ucsi.cerberus.model.IncidentReport", { ... }]}.
 *
 * <p>The {@link JsonTypeInfo} below enables class-name polymorphic typing for
 * {@code Report} values so each concrete report kind can be reconstructed on
 * import. Type resolution is constrained by the importer's configuration
 * (see {@code ReportImportService}).
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.WRAPPER_ARRAY)
public abstract class Report {

    private String id;
    private String title;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    /** Short label identifying the concrete report kind. */
    public abstract String kind();
}
