package ollamaat.agent;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Mutable counters/allowances for one agent run. */
public final class RunState {
    public final int runId;
    public final AtomicInteger requestsSent = new AtomicInteger();
    /** "tool|METHOD|host" keys the user approved for the rest of this run. */
    public final Set<String> allowances = ConcurrentHashMap.newKeySet();
    public volatile boolean cancelled;
    public volatile boolean allowNetwork = true;

    public RunState(int runId) { this.runId = runId; }
}
