package ollamaat.report;

/** What to include when rendering an HTML report. */
public final class ReportOptions {
    public String title = "AuditLens Security Assessment Report";
    public String targetScope = "";
    public String testerName = "";
    public boolean includeInfo = true;
    public boolean includeAuditLog = false;
    public boolean includeEvidence = true;
    /** Show the engine (local model name) on the HTML cover page. Turn off for reports shared outside the team. */
    public boolean showEngine = true;
    /** Organization shown on the cover page of both reports. */
    public String organization = "";
    /** Optional organization logo (PNG, JPEG or GIF). {@code logoExt} is png, jpeg or gif. */
    public byte[] logoBytes = new byte[0];
    public String logoExt = "png";
}
