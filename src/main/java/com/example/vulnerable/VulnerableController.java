package com.example.vulnerable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.sql.DataSource;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class VulnerableController {

    private static final Path DOCUMENTS_ROOT =
            Path.of("src/main/resources/documents").toAbsolutePath().normalize();

    // Conservative hostname/IPv4 allowlist: letters, digits, dots and hyphens only.
    private static final Pattern HOST_PATTERN =
            Pattern.compile("^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$");

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
        Path resolved = DOCUMENTS_ROOT.resolve(file).normalize();
        if (!resolved.startsWith(DOCUMENTS_ROOT)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid file path");
        }
        return Files.readString(resolved);
    }

    @GetMapping("/diagnostics")
    public String runDiagnostics(@RequestParam String host) {
        if (!HOST_PATTERN.matcher(host).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid host");
        }
        try {
            InetAddress address = InetAddress.getByName(host);
            boolean reachable = address.isReachable(2000);
            return "host " + host + " reachable=" + reachable;
        } catch (UnknownHostException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown host", e);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Unable to check host reachability", e);
        }
    }

    @GetMapping(value = "/welcome", produces = MediaType.TEXT_HTML_VALUE)
    public String welcome(@RequestParam String name) {
        return "<html><body><h1>Bienvenido " + name + "</h1></body></html>";
    }
}
