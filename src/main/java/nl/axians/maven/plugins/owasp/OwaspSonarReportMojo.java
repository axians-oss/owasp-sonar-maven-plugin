package nl.axians.maven.plugins.owasp;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.IOException;

/**
 * The {@link AbstractMojo} that is responsible for creating a SonarCloud/SonarQube custom report from the OWASP
 * dependency vulnerability check results produces by the OWASP {@code dependency-check-maven} plugin.
 * <p/>
 * See <a href="https://docs.sonarsource.com/sonarcloud/enriching/generic-issue-data/">here</a> for more information
 * about the  SonarCloud/SonarQube custom report format.
 */
@Mojo(name = "owasp-sonar-report", defaultPhase = LifecyclePhase.VERIFY)
public class OwaspSonarReportMojo extends AbstractMojo {

    /**
     * The location of the OWASP dependency check report.
     */
    @Parameter(name = "owaspReportFile", defaultValue = "target/dependency-check-report.json")
    File owaspReportFile;

    /**
     * The location of the OWASP dependency check report.
     */
    @Parameter(name = "sonarReportFile", defaultValue = "target/sonar-dependency-check-report.json")
    File sonarReportFile;

    @Override
    public void execute() throws MojoExecutionException {
        try {
            final OwaspSonarReportConverter converter = new OwaspSonarReportConverter();
            converter.convert(owaspReportFile, sonarReportFile);
        } catch (IOException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
    }

}
