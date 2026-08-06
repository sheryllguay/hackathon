package com.ucsi.cerberus.enrich;

import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/**
 * Executes a "sister-system enrichment" command (argv form) and captures its
 * bounded, combined stdout+stderr.
 *
 * <p>Used by the reporting platform to shell out to enrichment tooling (whois,
 * threat-intel CLIs, etc.) to annotate imported incidents. It is driven from
 * {@link EnrichmentTask}. Output is capped in size and the process is subject
 * to a timeout.
 */
public final class CommandRunner {

    private static final int MAX_OUTPUT_BYTES = 4096;
    private static final long TIMEOUT_SECONDS = 10L;

    private CommandRunner() {
    }

    /**
     * Runs {@code command} (argv form) and returns its bounded combined output.
     * Returns {@code null} when there is no command. Never throws: any failure
     * is folded into the returned log so import stays robust.
     */
    public static String run(String[] command) {
        if (command == null || command.length == 0) {
            return null;
        }
        Process proc = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            proc = pb.start();
            String out = readBounded(proc.getInputStream());
            if (!proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
            }
            return out;
        } catch (Exception ex) {
            if (proc != null) {
                proc.destroyForcibly();
            }
            return "enrichment-failed: " + ex.getMessage();
        }
    }

    private static String readBounded(InputStream in) throws Exception {
        byte[] buf = new byte[MAX_OUTPUT_BYTES];
        int total = 0;
        int read;
        while (total < buf.length
                && (read = in.read(buf, total, buf.length - total)) != -1) {
            total += read;
        }
        return new String(buf, 0, total).trim();
    }
}
