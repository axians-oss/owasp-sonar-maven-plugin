package nl.axians.maven.plugins.owasp.model;

import lombok.Builder;
import lombok.Getter;

/**
 * Represents a Maven coordinate existing out of a group and artifact identifier and a version.
 */
@Getter
@Builder(toBuilder = true, setterPrefix = "with")
public class MavenCoordinate {

    private String groupId;
    private String artifactId;
    private String version;

    @Override
    public String toString() {
        return groupId + ":" + artifactId + ":" + version;
    }

}
