package ollamaat.tools;

import ollamaat.Settings;

/** Global requests-per-second limiter for agent-originated traffic. */
public final class Throttle {
    private final Settings settings;
    private long next;

    public Throttle(Settings settings) { this.settings = settings; }

    public synchronized void acquire() {
        double rps = Math.max(0.1, settings.requestsPerSecond());
        long gap = (long) (1000.0 / rps), now = System.currentTimeMillis();
        long wait = next - now;
        if (wait > 0) {
            try { Thread.sleep(wait); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        next = Math.max(now, next) + gap;
    }
}
