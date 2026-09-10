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

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
public class VulnerableController {

    // Hostname o IPv4 simples; alcance intencionalmente acotado a lo que este endpoint de
    // diagnóstico necesita (no admite IPv6 ni IDN).
    private static final Pattern SAFE_HOST = Pattern.compile("^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$");
    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    private static final Path DOCUMENTS_DIRECTORY = Path.of("src/main/resources/documents").toAbsolutePath().normalize();
    // Visible en el paquete para permitir verificar en tests que se resuelve a una ruta absoluta.
    static final Path PING_EXECUTABLE = resolvePingExecutable();

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
    public String readDocument(@RequestParam String file) throws IOException {
        Path document = DOCUMENTS_DIRECTORY.resolve(file).normalize();
        if (!document.startsWith(DOCUMENTS_DIRECTORY)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid document path");
        }
        return Files.readString(document);
    }

    @GetMapping("/diagnostics")
    public String runDiagnostics(@RequestParam String host) throws IOException {
        if (!SAFE_HOST.matcher(host).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid host");
        }
        List<String> command = new ArrayList<>();
        command.add(PING_EXECUTABLE.toString());
        command.add(WINDOWS ? "-n" : "-c");
        command.add("1");
        command.add(host);
        Process process = new ProcessBuilder(command).start();
        return new String(process.getInputStream().readAllBytes());
    }

    @GetMapping(value = "/welcome", produces = MediaType.TEXT_HTML_VALUE)
    public String welcome(@RequestParam String name) {
        return "<html><body><h1>Bienvenido " + HtmlUtils.htmlEscape(name) + "</h1></body></html>";
    }

    private static Path resolvePingExecutable() {
        List<String> candidates = WINDOWS
                ? List.of("C:\\Windows\\System32\\PING.EXE")
                : List.of("/bin/ping", "/usr/bin/ping", "/sbin/ping");
        return candidates.stream()
                .map(Path::of)
                .filter(Files::isRegularFile)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No se encontró un binario de ping válido en este sistema"));
    }
}
