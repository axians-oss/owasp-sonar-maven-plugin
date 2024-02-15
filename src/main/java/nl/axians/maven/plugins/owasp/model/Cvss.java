package nl.axians.maven.plugins.owasp.model;

import lombok.Builder;
import lombok.Getter;

/**
 * CVSS (Common Vulnerability Scoring System) score.
 */
@Getter
@Builder(toBuilder = true, setterPrefix = "with")
public class Cvss {

    private String version;
    private String score;

}
