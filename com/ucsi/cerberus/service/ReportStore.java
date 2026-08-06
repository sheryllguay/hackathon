package com.ucsi.cerberus.service;

import com.ucsi.cerberus.model.Report;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store of successfully imported reports, keyed by report id.
 *
 * <p>Backs the {@code GET /report/view/:id} path. State is per-instance and is
 * cleared on restart.
 */
public class ReportStore {

    private final Map<String, Report> reports = new ConcurrentHashMap<>();

    public void save(Report report) {
        if (report != null && report.getId() != null) {
            reports.put(report.getId(), report);
        }
    }

    public Report get(String id) {
        return reports.get(id);
    }
}
