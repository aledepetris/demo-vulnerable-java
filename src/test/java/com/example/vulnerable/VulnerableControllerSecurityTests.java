package com.example.vulnerable;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression tests for the SAST findings reported on VulnerableController.
 * Each test targets one root cause from the approved remediation plan.
 */
@SpringBootTest
@AutoConfigureMockMvc
class VulnerableControllerSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void findUsersDoesNotAllowSqlInjectionThroughNameParameter() throws Exception {
        mockMvc.perform(get("/users").param("name", "nonexistent' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));
    }

    @Test
    void readDocumentRejectsPathTraversalOutsideDocumentsDirectory() throws Exception {
        mockMvc.perform(get("/documents").param("file", "../application.properties"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void readDocumentStillServesFilesInsideDocumentsDirectory() throws Exception {
        mockMvc.perform(get("/documents").param("file", "example.txt"))
                .andExpect(status().isOk());
    }

    @Test
    void runDiagnosticsRejectsHostWithShellMetacharacters() throws Exception {
        mockMvc.perform(get("/diagnostics").param("host", "localhost; echo INJECTED"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("INJECTED"))));
    }

    @Test
    void runDiagnosticsAcceptsAValidHostWithoutSpawningAProcess() throws Exception {
        mockMvc.perform(get("/diagnostics").param("host", "localhost"))
                .andExpect(status().isOk());
    }
}
