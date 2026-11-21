package ollamaat;

import burp.api.montoya.http.message.HttpHeader;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;

/** Tiny dynamic-proxy stub supporting no-arg returns plus header lookups (headerValue/header). */
public final class ScanStub {
    @SuppressWarnings("unchecked")
    public static <T> T stub(Class<T> c, Map<String, Object> methods, Map<String, String> headers) {
        return (T) Proxy.newProxyInstance(c.getClassLoader(), new Class<?>[]{c}, (proxy, method, args) -> {
            String name = method.getName();
            if ((name.equals("headerValue")) && args != null && args.length == 1)
                return headers.getOrDefault((String) args[0], headerCi(headers, (String) args[0]));
            if (methods.containsKey(name)) return methods.get(name);
            Class<?> rt = method.getReturnType();
            if (rt == boolean.class) return false;
            if (rt == int.class) return 0;
            if (rt == short.class) return (short) 0;
            if (rt == long.class) return 0L;
            if (rt == String.class) return "";
            if (rt == List.class) return List.of();
            return null;
        });
    }

    private static String headerCi(Map<String, String> headers, String key) {
        for (var e : headers.entrySet()) if (e.getKey().equalsIgnoreCase(key)) return e.getValue();
        return null;
    }

    public static HttpHeader header(String name, String value) {
        return stub(HttpHeader.class, Map.of("name", name, "value", value, "toString", name + ": " + value), Map.of());
    }
}
