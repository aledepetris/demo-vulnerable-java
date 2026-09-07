# Demo vulnerable Java

> **ADVERTENCIA:** este repositorio contiene vulnerabilidades deliberadas y dependencias antiguas.
> Es solo para probar herramientas de seguridad. No desplegar ni reutilizar su código.

Aplicación Spring Boot aislada para probar el flujo de remediación con hallazgos de GitHub.

## Hallazgos deliberados

### CodeQL

- SQL injection en `GET /users?name=...`.
- Path traversal en `GET /documents?file=...`.
- Command injection en `GET /diagnostics?host=...`.
- Reflected XSS en `GET /welcome?name=...`.

El workflow `.github/workflows/codeql.yml` analiza Java con la suite `security-extended`.

### Dependabot

El `pom.xml` declara versiones antiguas de Log4j, Commons Text y Commons FileUpload. El workflow de
dependency submission publica el grafo Maven y `.github/dependabot.yml` configura actualizaciones.

### Secret Scanning

`application-demo-secrets.properties` contiene únicamente credenciales públicas de ejemplo de AWS
y una conexión MongoDB ficticia contra `localhost`. Secret Scanning es una función de GitHub, no
un Action. Para detectar la conexión de prueba debe estar habilitada la opción de patrones
genéricos (`secret_scanning_non_provider_patterns`).

## Ejecución local

```powershell
mvn test
mvn spring-boot:run
```

La aplicación queda en `http://localhost:8080`. No debe exponerse fuera del equipo local.

## Automatizaciones

- CodeQL: GitHub Actions.
- Dependency Graph y SBOM: dependency submission workflow.
- Dependabot: configuración del repositorio y `dependabot.yml`.
- Secret Scanning: Security & Analysis del repositorio.
