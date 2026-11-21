package ollamaat.agent;

/** Recoverable tool problem; the message is returned to the model so it can correct itself. */
@SuppressWarnings("serial")
public class ToolException extends Exception {
    public ToolException(String m) { super(m); }
}
