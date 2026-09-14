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

import javax.sql.DataSource;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableController {

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
        return Files.readString(Path.of("src/main/resources/documents").resolve(file));
    }

    @GetMapping("/diagnostics")
    public String runDiagnostics(@RequestParam String host) throws IOException {
        Process process = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        return new String(process.getInputStream().readAllBytes());
    }

    @GetMapping(value = "/welcome", produces = MediaType.TEXT_HTML_VALUE)
    public String welcome(@RequestParam String name) {
        return "<html><body><h1>Bienvenido " + name + "</h1></body></html>";
    }
}
