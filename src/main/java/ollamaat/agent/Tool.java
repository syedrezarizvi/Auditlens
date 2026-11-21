package ollamaat.agent;

import java.util.List;
import java.util.Map;

/**
 * A capability the model can request. {@link #plan} must be side-effect free: it validates arguments and
 * returns an {@link Action} describing what WOULD happen. Only the policy layer decides whether exec runs.
 */
public interface Tool {
    String name();
    String description();
    /** JSON-schema "properties" object. */
    Map<String, Object> properties();
    List<String> required();
    Action plan(Args args) throws ToolException;
}
