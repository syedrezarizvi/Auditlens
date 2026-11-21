package ollamaat.agent;

import java.util.List;
import java.util.Map;

/** Lambda-friendly Tool implementation. */
public final class FnTool implements Tool {
    @FunctionalInterface public interface Planner { Action plan(Args a) throws Exception; }

    private final String name, desc;
    private final Schema schema;
    private final Planner planner;

    public FnTool(String name, String desc, Schema schema, Planner planner) {
        this.name = name; this.desc = desc; this.schema = schema; this.planner = planner;
    }

    public String name() { return name; }
    public String description() { return desc; }
    public Map<String, Object> properties() { return schema.props(); }
    public List<String> required() { return schema.required(); }

    public Action plan(Args a) throws ToolException {
        for (String r : schema.required()) a.req(r);
        try { return planner.plan(a); }
        catch (ToolException e) { throw e; }
        catch (Exception e) { throw new ToolException(e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
}
