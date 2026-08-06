package com.ucsi.cerberus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.ucsi.cerberus.model.Report;
import com.ucsi.cerberus.service.ReportImportService;
import com.ucsi.cerberus.service.ReportStore;
import com.ucsi.cerberus.service.SessionService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Cerberus Reports — application entry point.
 *
 * <p>An internal incident-report portal. Uses the JDK's built-in HTTP server
 * (no web framework) to keep the build lean and reproducible.
 *
 * <p>Endpoint surface:
 * <ul>
 *   <li>{@code POST /login}            — authenticate a portal user.</li>
 *   <li>{@code POST /report/import}    — import an uploaded report bundle.</li>
 *   <li>{@code GET  /report/view/:id}  — view a stored report.</li>
 *   <li>{@code GET  /admin/secret}     — read an admin-owned secret.</li>
 * </ul>
 */
public final class Main {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final SessionService SESSIONS = new SessionService();
    private static final ReportStore STORE = new ReportStore();
    private static final ReportImportService IMPORTER = new ReportImportService(STORE);

    private static final String FLAG_FILE =
            System.getenv().getOrDefault("FLAG_FILE", "/srv/cerberus/admin/secret.flag");

    private Main() {
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        server.createContext("/", Main::handleRoot);
        server.createContext("/login", Main::handleLogin);
        server.createContext("/report/import", Main::handleImport);
        server.createContext("/report/view/", Main::handleView);
        server.createContext("/admin/secret", Main::handleAdminSecret);

        // Serve requests from a fixed-size thread pool sized for expected
        // concurrent load; requests are short-lived.
        server.setExecutor(Executors.newFixedThreadPool(200));
        server.start();
        System.out.println("[cerberus] listening on :" + port + " as user " + System.getProperty("user.name"));
    }

    // ---- handlers -----------------------------------------------------------

    private static void handleRoot(HttpExchange ex) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("service", "Cerberus Incident-Report Portal");
        body.put("endpoints", new String[]{
                "POST /login", "POST /report/import", "GET /report/view/{id}", "GET /admin/secret"});
        sendJson(ex, 200, body);
    }

    private static void handleLogin(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        try {
            Map<?, ?> creds = JSON.readValue(readBody(ex), Map.class);
            Object u = creds.get("username");
            Object p = creds.get("password");
            String token = SESSIONS.login(u == null ? null : u.toString(), p == null ? null : p.toString());
            if (token == null) {
                sendError(ex, 401, "Invalid username or password.");
                return;
            }
            Map<String, Object> out = new HashMap<>();
            out.put("token", token);
            sendJson(ex, 200, out);
        } catch (Exception e) {
            sendError(ex, 400, "Missing credentials.");
        }
    }

    private static void handleImport(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        if (!authorized(ex)) {
            sendError(ex, 401, "Authentication required.");
            return;
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        try {
            ReportImportService.ImportResult result = IMPORTER.importBundle(readBody(ex));
            resp.put("status", "ok");
            resp.put("imported", result.getImported());
            if (result.getEnrichment() != null && !result.getEnrichment().isEmpty()) {
                resp.put("enrichment", result.getEnrichment());
            }
            sendJson(ex, 200, resp);
        } catch (ReportImportService.ImportException iex) {
            resp.put("status", "error");
            resp.put("error", iex.getMessage());
            sendJson(ex, 400, resp);
        }
    }

    private static void handleView(HttpExchange ex) throws IOException {
        if (!authorized(ex)) {
            sendError(ex, 401, "Authentication required.");
            return;
        }
        String path = ex.getRequestURI().getPath();
        String id = path.substring("/report/view/".length());
        Report report = STORE.get(id);
        if (report == null) {
            sendError(ex, 404, "No report with id: " + id);
            return;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", report.getId());
        out.put("title", report.getTitle());
        out.put("kind", report.kind());
        sendJson(ex, 200, out);
    }

    private static void handleAdminSecret(HttpExchange ex) throws IOException {
        if (!authorized(ex)) {
            sendError(ex, 401, "Authentication required.");
            return;
        }
        // Only return the secret when the file is readable by the current
        // process identity; otherwise report that access is denied.
        try {
            Path p = Paths.get(FLAG_FILE);
            if (!Files.isReadable(p)) {
                sendError(ex, 403, "Access denied: this secret is owned by report-admin.");
                return;
            }
            String flag = new String(Files.readAllBytes(p), StandardCharsets.UTF_8).trim();
            Map<String, Object> out = new HashMap<>();
            out.put("secret", flag);
            sendJson(ex, 200, out);
        } catch (Exception e) {
            sendError(ex, 403, "Access denied: this secret is owned by report-admin.");
        }
    }

    // ---- helpers ------------------------------------------------------------

    private static boolean authorized(HttpExchange ex) {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth == null) {
            return false;
        }
        String token = auth.startsWith("Bearer ") ? auth.substring("Bearer ".length()).trim() : auth.trim();
        return SESSIONS.isValid(token);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] all = readAll(in);
            return new String(all, StandardCharsets.UTF_8);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] payload = JSON.writeValueAsBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, payload.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(payload);
        }
    }

    private static void sendError(HttpExchange ex, int status, String message) throws IOException {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "error");
        out.put("error", message);
        sendJson(ex, status, out);
    }
}
