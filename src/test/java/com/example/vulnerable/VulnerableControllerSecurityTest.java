package com.example.vulnerable;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class VulnerableControllerSecurityTest {

    @Autowired
    private VulnerableController controller;

    @Test
    void findUsers_treatsSqlInjectionPayloadsAsData() throws Exception {
        assertEquals(List.of(), controller.findUsers("' OR '1'='1"));
        assertEquals(List.of(), controller.findUsers("x'; DROP TABLE users; --"));
        assertEquals(List.of("alice"), controller.findUsers("alice"));
    }

    @Test
    void readDocument_rejectsPathsOutsideDocumentDirectory() {
        String traversal = Path.of("..", "..", "..", "..", "pom.xml").toString();
        String absolute = Path.of("pom.xml").toAbsolutePath().toString();

        for (String maliciousPath : List.of(traversal, absolute)) {
            ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                    () -> controller.readDocument(maliciousPath));
            assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        }
    }

    @Test
    void readDocument_readsFilesInsideDocumentDirectory() throws Exception {
        assertFalse(controller.readDocument("example.txt").isBlank());
    }

    @Test
    void welcome_escapesUntrustedHtml() {
        String response = controller.welcome("<script>alert(1)</script>");

        assertTrue(response.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(response.contains("<script>"));
        assertTrue(controller.welcome("Ana").contains("Bienvenido Ana"));
    }
}
