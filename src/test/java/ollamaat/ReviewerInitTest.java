package ollamaat;

import burp.api.montoya.MontoyaApi;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/** Regression guard: AiPassiveCheck must build its PassiveReviewer with a NON-NULL engine. A field-initializer
 *  that read `engine` before the constructor assigned it once captured null, making every passive review throw
 *  NullPointerException ("Cannot read field \"llm\" because \"this.engine\" is null"). */
public final class ReviewerInitTest {
    public static void main(String[] a) throws Exception {
        Map<String, String> prefs = new HashMap<>();
        Map<String, Function<Object[], Object>> o = new HashMap<>();
        o.put("Preferences.getString", x -> prefs.get(x[0]));
        o.put("Preferences.setString", x -> { prefs.put((String) x[0], (String) x[1]); return null; });
        o.put("PersistedObject.getString", x -> null);
        o.put("PersistedObject.setString", x -> null);
        MontoyaApi api = SmokeTest.stub(MontoyaApi.class, o);
        Engine engine = new Engine(api);

        int fails = 0;
        // 1) The passive check's reviewer holds the real engine.
        AiPassiveCheck check = new AiPassiveCheck(engine);
        Object reviewer = get(check, "reviewer");
        fails += assertTrue(reviewer != null, "AiPassiveCheck.reviewer is constructed");
        Object revEngine = get(reviewer, "engine");
        fails += assertTrue(revEngine == engine, "PassiveReviewer.engine == the engine passed in (not null)");

        // 2) Engine's own on-demand reviewer also holds a non-null engine.
        Object engReviewer = get(engine, "reviewer");
        fails += assertTrue(engReviewer != null && get(engReviewer, "engine") != null, "Engine.reviewer has a non-null engine");

        System.out.println();
        System.out.println((3 - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static Object get(Object target, String field) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        return f.get(target);
    }

    static int assertTrue(boolean ok, String what) { System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
