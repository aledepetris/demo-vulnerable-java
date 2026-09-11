package com.example.vulnerable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class VulnerableController {

    // Base directory documents are confined to; requested files must resolve within it.
    private static final Path DOCUMENTS_BASE = Path.of("src/main/resources/documents").toAbsolutePath().normalize();

    // Only hostnames/IP literals are accepted; shell metacharacters are rejected outright.
    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$");

    private static final String PING_EXECUTABLE = resolvePingExecutable();

    private final DataSource dataSource;

    public VulnerableController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/users")
    public List<String> findUsers(@RequestParam String name) throws SQLException {
        String query = "SELECT name FROM users WHERE name = ?";
        List<String> users = new ArrayList<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(query)) {
            statement.setString(1, name);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    users.add(results.getString("name"));
                }
            }
        }
        return users;
    }

    @GetMapping("/documents")
    public ResponseEntity<String> readDocument(@RequestParam String file) throws IOException {
        Path candidate = DOCUMENTS_BASE.resolve(file).normalize();
        if (!candidate.startsWith(DOCUMENTS_BASE)) {
            return ResponseEntity.badRequest().body("Invalid file path");
        }
        return ResponseEntity.ok(Files.readString(candidate));
    }

    @GetMapping("/diagnostics")
    public ResponseEntity<String> runDiagnostics(@RequestParam String host) throws IOException {
        if (!HOST_PATTERN.matcher(host).matches()) {
            return ResponseEntity.badRequest().body("Invalid host");
        }
        Process process = new ProcessBuilder(buildPingCommand(host)).start();
        return ResponseEntity.ok(new String(process.getInputStream().readAllBytes()));
    }

    @GetMapping(value = "/welcome", produces = MediaType.TEXT_HTML_VALUE)
    public String welcome(@RequestParam String name) {
        return "<html><body><h1>Bienvenido " + HtmlUtils.htmlEscape(name) + "</h1></body></html>";
    }

    // Builds an argument vector (no shell) so the host cannot inject additional commands.
    static List<String> buildPingCommand(String host) {
        String countFlag = isWindows() ? "-n" : "-c";
        return List.of(PING_EXECUTABLE, countFlag, "1", host);
    }

    // Resolves the ping executable via an absolute, OS-specific path instead of a
    // PATH-dependent relative command name.
    static String resolvePingExecutable() {
        return isWindows() ? "C:\\Windows\\System32\\PING.EXE" : "/bin/ping";
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
