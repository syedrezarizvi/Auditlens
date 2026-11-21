package ollamaat.scan;

import java.util.List;
import java.util.regex.Pattern;

/** Payload markers, detection signatures and parameter-name heuristics shared by the active checks. */
public final class Signatures {
    private Signatures() {}

    public static String marker() {
        return "oat" + Long.toHexString(System.nanoTime() & 0xFFFFFF);
    }

    // ---- SQL error fingerprints (vendor-agnostic sample; deliberately not exhaustive) ----
    public static final Pattern SQL_ERROR = Pattern.compile("(?i)(sql syntax|unclosed quotation mark|quoted string not properly terminated|"
            + "pg::syntaxerror|psqlexception|sqlite3::|sqlstate\\[|ora-\\d{5}|microsoft ole db provider|odbc (?:sql|driver)|sqlexception|"
            + "pdoexception|mysql_fetch|mysqli_|com\\.mysql\\.jdbc|System\\.Data\\.SqlClient|npgsql\\.|sequelize)");

    public static final Pattern SERVER_ERROR_SIGNATURE = Pattern.compile("(?i)(exception|traceback \\(most recent|stack trace|at [a-zA-Z0-9_.$]+\\([A-Za-z]+\\.java:\\d+\\)|"
            + "fatal error|unhandled exception|internal server error|whitelabel error page)");

    public static final Pattern DIRECTORY_LISTING = Pattern.compile("(?i)(<title>index of /|Index of /[^<]*</title>|Parent Directory</a>)");

    public static final List<String> SENSITIVE_PATHS = List.of(
            "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/web.config", "/.DS_Store",
            "/actuator/env", "/actuator/health", "/swagger.json", "/openapi.json", "/api-docs",
            "/.well-known/security.txt", "/backup.zip", "/.svn/entries", "/config.php.bak", "/wp-config.php.bak");

    // ---- parameter-name heuristics (keep targeted checks low-volume and relevant) ----
    // Boundaries are letters only (not \b, which treats '_' as a word character and would miss snake_case
    // names like "template_path" or "redirect_url"); a letter immediately before/after still blocks a match,
    // so this won't fire on an unrelated word that merely contains the keyword as a substring (e.g. "profile").
    public static final Pattern FILE_PARAM = Pattern.compile("(?i)(?<![a-z])(file|path|template|page|doc|dir|folder|include|src|lang|locale|filename)(?![a-z])");
    public static final Pattern REDIRECT_PARAM = Pattern.compile("(?i)(?<![a-z])(url|redirect|next|return|returnurl|callback|dest|destination|uri|target|continue|out|view|link)(?![a-z])");
    public static final Pattern COMMAND_PARAM = Pattern.compile("(?i)(?<![a-z])(cmd|command|exec|host|ip|ping|traceroute|dns|lookup|convert|run|shell|query)(?![a-z])");
}
