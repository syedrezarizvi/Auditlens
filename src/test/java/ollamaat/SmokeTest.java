package ollamaat;

import burp.api.montoya.MontoyaApi;
import ollamaat.ui.MainPanel;

import javax.swing.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/** Headless end-to-end smoke test: real Engine + BurpTools + Swing panel over a stubbed MontoyaApi and a mock Ollama. */
public class SmokeTest {
    static final Map<String, String> PREFS = new HashMap<>(), EXT = new HashMap<>();

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> c, Map<String, Function<Object[], Object>> over) {
        return (T) Proxy.newProxyInstance(c.getClassLoader(), new Class<?>[]{c}, (p, m, a) -> {
            Function<Object[], Object> f = over.get(c.getSimpleName() + "." + m.getName());
            if (f != null) return f.apply(a);
            if (m.getDeclaringClass() == Object.class) return m.getName().equals("toString") ? "stub" : m.getName().equals("hashCode") ? 1 : p == a[0];
            Class<?> r = m.getReturnType();
            if (r == c) return p;
            if (r == boolean.class) return false;
            if (r.isPrimitive()) return r == void.class ? null : 0;
            if (r == String.class) return "";
            if (r == List.class) return List.of();
            if (r.isInterface()) return stub(r, over);
            return null;
        });
    }

    static MontoyaApi api() {
        Map<String, Function<Object[], Object>> o = new HashMap<>();
        o.put("Preferences.getString", a -> PREFS.get(a[0]));
        o.put("Preferences.setString", a -> { PREFS.put((String) a[0], (String) a[1]); return null; });
        o.put("PersistedObject.getString", a -> EXT.get(a[0]));
        o.put("PersistedObject.setString", a -> { EXT.put((String) a[0], (String) a[1]); return null; });
        o.put("Scope.isInScope", a -> ((String) a[0]).startsWith("https://app.test/"));
        return stub(MontoyaApi.class, o);
    }

    public static void main(String[] x) throws Exception {
        System.setProperty("java.awt.headless", "true");
        Map<String, Function<Object[], Object>> fo = new HashMap<>();
        fo.put("MontoyaObjectFactory.httpRequestFromUrl", a -> {
            Map<String, Function<Object[], Object>> ro = new HashMap<>();
            ro.put("HttpRequest.url", b -> a[0]);
            ro.put("HttpRequest.method", b -> "GET");
            return stub(burp.api.montoya.http.message.requests.HttpRequest.class, ro);
        });
        burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = stub(burp.api.montoya.internal.MontoyaObjectFactory.class, fo);
        SelfTest.Mock mock = new SelfTest.Mock();
        int fails = 0;
        try {
            MontoyaApi api = api();
            Engine engine = new Engine(api);
            engine.settings.llmProvider(Settings.PROVIDER_OLLAMA);
            engine.settings.ollamaUrl(mock.url());
            engine.settings.model("qwen3:8b");
            check(engine.skills().all().size() >= 10, "engine loads skills");
            MainPanel[] panel = new MainPanel[1];
            SwingUtilities.invokeAndWait(() -> panel[0] = new MainPanel(engine));
            check(panel[0].getComponentCount() > 0, "MainPanel constructs headless");

            String jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.";
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("scope_check", "url", "https://app.test/a"), SelfTest.call("scope_check", "url", "https://other.test/a"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("convert", "value", jwt, "kind", "jwt"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("convert", "value", "hello world", "kind", "base64", "direction", "encode"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("list_proxy_history"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("send_request", "url", "https://other.test/steal"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("note_add", "title", "Roles", "text", "jwt carries role claim"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("load_skill", "name", "jwt-review"))));
            mock.script.add(SelfTest.chat("", List.of(SelfTest.call("finish", "summary", "smoke ok"))));

            CountDownLatch done = new CountDownLatch(1);
            List<String> ev = Collections.synchronizedList(new ArrayList<>());
            boolean started = engine.start("smoke", List.of("recon-mapping"), "ctx line", true, (t, s) -> ev.add(t + ":" + s), done::countDown);
            check(started, "run starts");
            check(done.await(30, TimeUnit.SECONDS), "run completes");
            String all = String.join("\n", ev);
            check(all.contains("IN scope") && all.contains("NOT in scope"), "scope_check works");
            check(all.contains("alg") && all.contains("NOT verified"), "jwt decode works");
            check(all.contains("aGVsbG8gd29ybGQ="), "base64 encode works");
            check(all.contains("No in-scope items"), "list_proxy_history handles empty history with scope hint");
            check(all.contains("Blocked: out of Burp target scope"), "out-of-scope send_request blocked end-to-end");
            check(engine.memory.notes().size() == 1 && engine.memory.notes().get(0).title().equals("Roles"), "note persisted in memory");
            check(EXT.get("ollamaat.notes") != null && EXT.get("ollamaat.audit") != null, "notes+audit written to project persistence");
            check(engine.audit.all().stream().anyMatch(e -> e.verdict().equals("BLOCKED")), "audit has BLOCKED entry");
            check(mock.requests.get(0).contains("SKILL recon-mapping") && mock.requests.get(0).contains("ctx line"), "preloaded skill + context sent");
            check(all.contains("DONE:smoke ok"), "DONE event with summary");

            // second run sees the memory digest in the system prompt
            mock.requests.clear();
            mock.script.add(SelfTest.chat("nothing more", null));
            CountDownLatch d2 = new CountDownLatch(1);
            engine.start("again", List.of(), "", false, (t, s) -> { }, d2::countDown);
            d2.await(15, TimeUnit.SECONDS);
            check(mock.requests.get(0).contains("NOTE Roles") && !mock.requests.get(0).contains("\"name\":\"send_request\""), "memory digest injected; read-only run hides network tools");
        } finally { mock.stop(); }
        System.out.println(fails == 0 ? "SMOKE OK" : "SMOKE FAILED");
        System.exit(fails == 0 ? 0 : 1);
    }

    static void check(boolean c, String n) {
        System.out.println((c ? "  ok   " : "  FAIL ") + n);
        if (!c) { System.out.println("SMOKE FAILED"); System.exit(1); }
    }
}
