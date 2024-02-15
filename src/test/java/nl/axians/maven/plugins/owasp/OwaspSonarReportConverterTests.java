package nl.axians.maven.plugins.owasp;

import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * This class contains tests for the {@link OwaspSonarReportConverter}.
 */
public class OwaspSonarReportConverterTests {

    @Test
    public void Should_ConvertOwaspReportToSonarReport() throws IOException, JSONException {
        // Arrange
        OwaspSonarReportConverter converter = new OwaspSonarReportConverter();
        File owaspReportFile = new File("src/test/resources/dependency-check-report.json");
        File sonarReportFile = new File("target/sonar-dependency-check-report.json");
        File expectedSonarReportFile = new File("src/test/resources/sonar-dependency-check-report.json");

        // Act
        converter.convert(owaspReportFile, sonarReportFile);

        // Assert
        final String actual = Files.readString(sonarReportFile.toPath());
        final String expected = Files.readString(expectedSonarReportFile.toPath());
        JSONAssert.assertEquals(expected, actual, true);
    }

}
