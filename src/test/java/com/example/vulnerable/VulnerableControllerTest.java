package com.example.vulnerable;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression tests for the CodeQL findings fixed in VulnerableController:
 * java/sql-injection, java/path-injection, java/command-line-injection,
 * java/relative-path-command and java/xss.
 */
@SpringBootTest
@AutoConfigureMockMvc
// Uses its own in-memory database name so this context (which differs from
// VulnerableApplicationTests' plain context) doesn't collide with schema.sql
// re-initialization against a shared "vulnerable" H2 database in the same JVM.
@TestPropertySource(properties = "spring.datasource.url=jdbc:h2:mem:vulnerable-controller-test")
class VulnerableControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void findUsers_returnsMatchingUser() throws Exception {
        mockMvc.perform(get("/users").param("name", "alice"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("alice")));
    }

    @Test
    void findUsers_treatsSqlPayloadAsLiteralData() throws Exception {
        mockMvc.perform(get("/users").param("name", "alice' OR '1'='1"))
            .andExpect(status().isOk())
            .andExpect(content().string("[]"));
    }

    @Test
    void readDocument_returnsContentForAllowedFile() throws Exception {
        mockMvc.perform(get("/documents").param("file", "example.txt"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("harmless document")));
    }

    @Test
    void readDocument_rejectsPathTraversal() throws Exception {
        mockMvc.perform(get("/documents").param("file", "../../../../etc/passwd"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void readDocument_rejectsAbsolutePathEscape() throws Exception {
        mockMvc.perform(get("/documents").param("file", "/etc/passwd"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void runDiagnostics_rejectsShellMetacharacters() throws Exception {
        mockMvc.perform(get("/diagnostics").param("host", "localhost; id"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void runDiagnostics_rejectsCommandSubstitution() throws Exception {
        mockMvc.perform(get("/diagnostics").param("host", "$(whoami)"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void buildPingCommand_usesAbsoluteExecutablePath() {
        List<String> command = VulnerableController.buildPingCommand("localhost");

        assertThat(Path.of(command.get(0)).isAbsolute())
            .as("the ping executable must be invoked via an absolute path, not a shell-resolved relative command")
            .isTrue();
        assertThat(command).contains("localhost");
    }

    @Test
    void welcome_escapesHtmlInName() throws Exception {
        mockMvc.perform(get("/welcome").param("name", "<script>alert(1)</script>"))
            .andExpect(status().isOk())
            .andExpect(content().string(not(containsString("<script>"))))
            .andExpect(content().string(containsString("&lt;script&gt;")));
    }
}
