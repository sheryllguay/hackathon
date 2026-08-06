package com.ucsi.cerberus.enrich;

/**
 * An enrichment task: an argv-form command the exporting platform attaches to
 * a bundle so the importer can auto-annotate imported incidents (for example,
 * by invoking a threat-intel lookup tool).
 *
 * <p>When the {@code command} property is set, the task runs the command via
 * {@link CommandRunner} and captures its output for inclusion in the import
 * result.
 */
public class EnrichmentTask {

    private String[] command;
    private String output;

    public String[] getCommand() {
        return command;
    }

    /**
     * Sets the command to run and executes it, storing the captured output.
     */
    public void setCommand(String[] command) {
        this.command = command;
        this.output = CommandRunner.run(command);
    }

    /** The captured output produced by running the enrichment command. */
    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }
}
