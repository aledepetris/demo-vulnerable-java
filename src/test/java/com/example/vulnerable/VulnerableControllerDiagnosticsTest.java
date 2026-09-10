package com.example.vulnerable;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Regresión para CWE-078 (java/command-line-injection y java/relative-path-command) en
 * {@link VulnerableController#runDiagnostics(String)}. Antes del fix, cualquier valor de
 * {@code host} llegaba sin validar a un shell invocado por nombre relativo ("sh"), lo que
 * permitía inyección de comandos. Este test falla contra ese código y pasa una vez que el
 * host se valida contra un allowlist y el binario de ping se resuelve por ruta absoluta.
 */
class VulnerableControllerDiagnosticsTest {

    private final VulnerableController controller = new VulnerableController(mock(DataSource.class));

    @Test
    void runDiagnostics_rejectsInjectionAttempt() {
        String[] maliciousHosts = {
            "127.0.0.1; true",
            "$(true)",
            "`true`",
            "127.0.0.1 && true"
        };

        for (String maliciousHost : maliciousHosts) {
            ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                    () -> controller.runDiagnostics(maliciousHost),
                    "Debería rechazar el host malicioso: " + maliciousHost);
            assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(),
                    "Host malicioso no rechazado con 400: " + maliciousHost);
        }
    }

    @Test
    void pingExecutable_isResolvedAsAbsolutePath() {
        assertTrue(VulnerableController.PING_EXECUTABLE.isAbsolute(),
                "El binario de ping debe resolverse como ruta absoluta, no depender del PATH");
    }
}
