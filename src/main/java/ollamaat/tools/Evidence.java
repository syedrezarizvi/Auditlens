package ollamaat.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import ollamaat.agent.ToolException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stable handles for HTTP messages: pN = Proxy history id N, aN = sent by the agent, sN = selected by the pentester.
 * The model only ever sees refs, never object identities, so it cannot reach anything the user did not expose.
 */
public final class Evidence {
    private final MontoyaApi api;
    /** Cap on retained agent/selected message handles, so a long engagement with many findings cannot grow the
     *  heap without bound (BApp criterion: cope with large projects). The oldest handles are evicted first; an
     *  evicted ref simply resolves as unknown, and callers fall back to the site map. */
    private static final int MAX_ITEMS = 2000;
    private final Map<String, HttpRequestResponse> items = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<>(256, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, HttpRequestResponse> e) {
                    return size() > MAX_ITEMS;
                }
            });
    private final AtomicInteger agentSeq = new AtomicInteger(), selSeq = new AtomicInteger();
    private volatile long cachedAt;
    private volatile List<ProxyHttpRequestResponse> cachedList = List.of();
    private volatile Map<Integer, ProxyHttpRequestResponse> cachedIndex = Map.of();

    public Evidence(MontoyaApi api) { this.api = api; }

    /** Snapshot of proxy history, cached briefly because history() copies the whole list. */
    public synchronized List<ProxyHttpRequestResponse> proxy() {
        long now = System.currentTimeMillis();
        if (now - cachedAt > 2000) {
            List<ProxyHttpRequestResponse> l = api.proxy().history();
            Map<Integer, ProxyHttpRequestResponse> idx = new HashMap<>(l.size() * 2);
            for (ProxyHttpRequestResponse p : l) idx.put(p.id(), p);
            cachedList = l;
            cachedIndex = idx;
            cachedAt = now;
        }
        return cachedList;
    }

    public ProxyHttpRequestResponse proxyItem(int id) {
        proxy();
        return cachedIndex.get(id);
    }

    public String addAgent(HttpRequestResponse rr) {
        String ref = "a" + agentSeq.incrementAndGet();
        items.put(ref, rr);
        return ref;
    }

    public String addSelected(HttpRequestResponse rr) {
        String ref = "s" + selSeq.incrementAndGet();
        items.put(ref, rr);
        return ref;
    }

    /**
     * Resolves a ref only when the request it points to is on one of the finding's hosts. Agent and selected refs
     * ("a3", "s1") are numbered per session and are not persisted, so a ref saved in an earlier session can point at
     * unrelated traffic after a restart. Returns null when the ref is unknown or points at another host.
     */
    public HttpRequestResponse forFinding(String ref, java.util.Collection<String> findingUrls) {
        HttpRequestResponse rr;
        try { rr = get(ref); } catch (Exception e) { return null; }
        java.util.Set<String> wanted = new java.util.HashSet<>();
        if (findingUrls != null) for (String u : findingUrls) {
            String h = hostOf(u);
            if (h != null) wanted.add(h.toLowerCase(java.util.Locale.ROOT));
        }
        if (wanted.isEmpty()) return rr;
        String got = hostOf(rr.request().url());
        return got != null && wanted.contains(got.toLowerCase(java.util.Locale.ROOT)) ? rr : null;
    }

    /** Host part of a URL, or null when it cannot be read. */
    public static String hostOf(String url) {
        if (url == null || url.isBlank()) return null;
        try { return java.net.URI.create(url.trim()).getHost(); } catch (RuntimeException e) { return null; }
    }

    public HttpRequestResponse get(String refIn) throws ToolException {
        String ref = refIn == null ? "" : refIn.trim().replace("#", "").toLowerCase();
        if (ref.matches("\\d+")) ref = "p" + ref;
        if (ref.startsWith("p")) {
            try {
                ProxyHttpRequestResponse p = proxyItem(Integer.parseInt(ref.substring(1)));
                if (p == null) throw new ToolException("No proxy history item " + ref);
                return HttpRequestResponse.httpRequestResponse(p.finalRequest(), p.response());
            } catch (NumberFormatException e) { throw new ToolException("Bad ref '" + refIn + "'"); }
        }
        HttpRequestResponse rr = items.get(ref);
        if (rr == null) throw new ToolException("Unknown ref '" + refIn + "'. Use refs returned by other tools (p12, a3, s1).");
        return rr;
    }
}
