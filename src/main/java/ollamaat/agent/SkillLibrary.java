package ollamaat.agent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/** Methodology "skills": markdown files with name/description front matter, loaded on demand by the agent. */
public final class SkillLibrary {
    public record Skill(String name, String description, String body, boolean builtin) {}

    private final Map<String, Skill> skills = new TreeMap<>();

    public static SkillLibrary load(String userDir) {
        SkillLibrary lib = new SkillLibrary();
        try (InputStream in = SkillLibrary.class.getResourceAsStream("/skills/index.txt")) {
            if (in != null) for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                String f = line.trim();
                if (f.isEmpty()) continue;
                try (InputStream si = SkillLibrary.class.getResourceAsStream("/skills/" + f)) {
                    if (si != null) lib.add(parse(new String(si.readAllBytes(), StandardCharsets.UTF_8), f, true));
                }
            }
        } catch (IOException ignored) { }
        if (userDir != null && !userDir.isBlank()) {
            try (Stream<Path> s = Files.list(Paths.get(userDir))) {
                for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".md"))::iterator)
                    lib.add(parse(Files.readString(p), p.getFileName().toString(), false));
            } catch (IOException | RuntimeException ignored) { }
        }
        return lib;
    }

    private void add(Skill s) { if (s != null) skills.put(s.name(), s); }

    static Skill parse(String text, String fileName, boolean builtin) {
        String name = fileName.replaceAll("\\.md$", ""), desc = "", body = text;
        if (text.startsWith("---")) {
            int end = text.indexOf("\n---", 3);
            if (end > 0) {
                for (String l : text.substring(3, end).split("\\R")) {
                    int c = l.indexOf(':');
                    if (c < 0) continue;
                    String k = l.substring(0, c).trim(), v = l.substring(c + 1).trim();
                    if (k.equals("name") && !v.isEmpty()) name = v;
                    if (k.equals("description")) desc = v;
                }
                body = text.substring(end + 4).trim();
            }
        }
        return new Skill(name, desc, body, builtin);
    }

    public Collection<Skill> all() { return skills.values(); }
    public Skill get(String name) { return name == null ? null : skills.get(name.trim()); }
    public String catalog() {
        StringBuilder sb = new StringBuilder();
        for (Skill s : skills.values()) sb.append("- ").append(s.name()).append(": ").append(s.description()).append('\n');
        return sb.toString();
    }
}
