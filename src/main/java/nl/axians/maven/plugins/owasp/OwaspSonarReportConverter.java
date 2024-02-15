package nl.axians.maven.plugins.owasp;

import jakarta.json.*;
import nl.axians.maven.plugins.owasp.model.Cvss;
import nl.axians.maven.plugins.owasp.model.MavenCoordinate;
import nl.axians.maven.plugins.owasp.model.Vulnerability;

import java.io.*;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The {@link OwaspSonarReportConverter} is responsible for converting the OWASP dependency check report to a
 * SonarCloud/SonarQube custom report.
 */
public class OwaspSonarReportConverter {

    /**
     * Convert the OWASP dependency check report to a SonarCloud/SonarQube custom report.
     *
     * @param theOwaspReportFile The OWASP dependency check report file in JSON format.
     * @param theSonarReportFile The SonarCloud/SonarQube custom report file.
     * @throws IOException If any I/O error occurs.
     */
    public void convert(final File theOwaspReportFile, final File theSonarReportFile) throws IOException {
        try (JsonReader reader = Json.createReader(Files.newInputStream(theOwaspReportFile.toPath()))) {
            final JsonArray rules = createRules();

            // Get the vulnerabilities.
            final JsonArrayBuilder issueBuilder = Json.createArrayBuilder();
            getVulnerabilities(reader, issueBuilder);

            // Create the Sonar report.
            final JsonObjectBuilder sonarReport = Json.createObjectBuilder();
            sonarReport.add("rules", rules);
            sonarReport.add("issues", issueBuilder);

            // Write the Sonar report.
            final JsonWriterFactory writerFactory = Json.createWriterFactory(Collections.emptyMap());
            try (final JsonWriter writer = writerFactory.createWriter(Files.newOutputStream(theSonarReportFile.toPath()))) {
                writer.writeObject(sonarReport.build());
            }
        }
    }

    /**
     * Create the rules section of the Sonar report. This will contain one rule for OWASP dependency vulnerabilities,
     * which will be referenced by the found vulnerabilities in the issues section.
     *
     * @return The rules section of the Sonar report.
     */
    private static JsonArray createRules() {
        final JsonObject impact = Json.createObjectBuilder()
                .add("softwareQuality", "SECURITY")
                .add("severity", "MEDIUM")
                .build();

        final JsonObject rule = Json.createObjectBuilder()
                .add("id", "owasp1")
                .add("name", "OWASP dependency vulnerability")
                .add("description", "Vulnerabilities found by OWASP dependency check Maven plugin.")
                .add("engineId", "dependency-check-maven")
                .add("cleanCodeAttribute", "TRUSTWORTHY")
                .add("impacts", Json.createArrayBuilder().add(impact))
                .build();

        return Json.createArrayBuilder()
                .add(rule)
                .build();
    }

    /**
     * Get the OWASP vulnerabilities from the OWASP report and return them as an array of Sonar issues.
     *
     * @param theReader       {@link JsonReader} with the OWASP vulnerability report.
     * @param theIssueBuilder The {@link JsonArrayBuilder} where to add the Sonar issues to.
     */
    private void getVulnerabilities(final JsonReader theReader, final JsonArrayBuilder theIssueBuilder) {
        final JsonArray dependencies = theReader.readObject().getJsonArray("dependencies");
        dependencies.stream()
                .filter(dependency -> dependency.asJsonObject().containsKey("vulnerabilities"))
                .forEach(dependency -> extractAndAddVulnerabilities(dependency, theIssueBuilder));
    }

    /**
     * Extract the vulnerabilities from the specified {@code dependency} and add it to the specified
     * {@code issueBuilder}.
     *
     * @param theDependency   The dependency where to extract the vulnerability from.
     * @param theIssueBuilder The {@link JsonArrayBuilder} where to add the vulnerability to.
     */
    private void extractAndAddVulnerabilities(final JsonValue theDependency, final JsonArrayBuilder theIssueBuilder) {
        final JsonArray vulnerabilities = theDependency.asJsonObject().getJsonArray("vulnerabilities");
        vulnerabilities.stream()
                .map(aVulnerability -> {
                    final JsonObject vulnerability = aVulnerability.asJsonObject();

                    final Cvss cvss = getCvss(vulnerability);
                    final List<String> cwes = getCwes(vulnerability);
                    final MavenCoordinate packageCoordinate = getPackageCoordinate(theDependency.asJsonObject());
                    final MavenCoordinate includedByCoordinate = getIncludedByCoordinate(theDependency.asJsonObject());

                    return Vulnerability.builder()
                            .withEngineId(vulnerability.getString("source"))
                            .withDescription(vulnerability.getString("description"))
                            .withRuleId(vulnerability.getString("name"))
                            .withOwaspSeverity(vulnerability.getString("severity"))
                            .withSonarSeverity(toSonarSeverity(vulnerability.getString("severity")))
                            .withCvss(cvss)
                            .withCwes(cwes)
                            .withFileName("pom.xml")
                            .withPackageCoordinate(packageCoordinate)
                            .withIncludedByCoordinate(includedByCoordinate)
                            .build();
                })
                .forEach(aVulnerability -> theIssueBuilder.add(aVulnerability.toJsonObject()));
    }

    /**
     * Get the package Maven coordinate.
     *
     * @param theDependency The dependency for which to get the Maven coordinate.
     * @return The Maven coordinate of the package or {@code null}.
     */
    private MavenCoordinate getIncludedByCoordinate(final JsonObject theDependency) {
        if (theDependency.containsKey("includedBy")) {
            final JsonArray packages = theDependency.getJsonArray("includedBy");
            final String coordinate = packages.get(0).asJsonObject().getString("reference");
            final String[] parts = coordinate.split("/");
            return MavenCoordinate.builder()
                    .withGroupId(parts[1])
                    .withArtifactId(parts[2].substring(0, parts[2].indexOf('@')))
                    .withVersion(parts[2].substring(parts[2].indexOf('@') + 1))
                    .build();
        }

        return null;
    }

    /**
     * Get the package Maven coordinate.
     *
     * @param theDependency The dependency for which to get the Maven coordinate.
     * @return The Maven coordinate of the package or {@code null}.
     */
    private MavenCoordinate getPackageCoordinate(final JsonObject theDependency) {
        if (theDependency.containsKey("packages")) {
            final JsonArray packages = theDependency.getJsonArray("packages");
            final String coordinate = packages.get(0).asJsonObject().getString("id");
            final String[] parts = coordinate.split("/");
            return MavenCoordinate.builder()
                    .withGroupId(parts[1])
                    .withArtifactId(parts[2].substring(0, parts[2].indexOf('@')))
                    .withVersion(parts[2].substring(parts[2].indexOf('@') + 1))
                    .build();
        }

        return null;
    }

    /**
     * Get the Common Weakness Enumeration Standard for the specified vulnerability.
     *
     * @param theVulnerability The vulnerability.
     * @return The CWES of the vulnerability if any specified.
     */
    private List<String> getCwes(final JsonObject theVulnerability) {
        if (theVulnerability.containsKey("cwes")) {
            return theVulnerability.getJsonArray("cwes").stream().map(JsonValue::toString).collect(Collectors.toList());
        }

        return Collections.emptyList();
    }

    /**
     * Get the Common Vulnerability Scoring System for the specified vulnerability.
     *
     * @param theVulnerability The vulnerability.
     * @return The {@link Cvss} of the vulnerability if any specified.
     */
    private Cvss getCvss(final JsonObject theVulnerability) {
        if (theVulnerability.containsKey("cvssv3")) {
            final JsonObject cvss = theVulnerability.getJsonObject("cvssv3");
            return Cvss.builder()
                    .withVersion("cvssv3")
                    .withScore(cvss.getJsonNumber("baseScore").toString())
                    .build();
        } else if (theVulnerability.containsKey("cvssv2")) {
            final JsonObject cvss = theVulnerability.getJsonObject("cvssv2");
            return Cvss.builder()
                    .withVersion("cvssv2")
                    .withScore(cvss.getJsonNumber("score").toString())
                    .build();
        } else {
            return null;
        }
    }

    /**
     * Convert a OWASP dependency check severity to a Sonar severity.
     *
     * @param theSeverity The OWASP dependency check severity.
     * @return The Sonar severity.
     */
    private String toSonarSeverity(final String theSeverity) {
        switch (theSeverity) {
            case "CRITICAL":
                return "CRITICAL";
            case "HIGH":
                return "MAJOR";
            case "MEDIUM":
            case "Low":
                return "MINOR";
            default:
                return "INFO";
        }
    }

}
