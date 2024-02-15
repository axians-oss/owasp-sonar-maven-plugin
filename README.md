# OWASP Sonar Maven Plugin

This plugin is used to convert results of the OWASP `dependency-check-maven` plugin to something that SonarCloud can process. The `dependency-check-maven`plugin is used to check for vulnerabilities in the dependencies of a project, but SonarCloud can not process its output directly. 

## Usage
To use this plugin add the following to your project's `pom.xml`:
```xml
<build>
    <plugins>
        <plugin>
            <groupId>nl.axians</groupId>
            <artifactId>owasp-sonar-maven-plugin</artifactId>
            <version>1.0.0</version>
            <dependencies>
                <dependency>
                    <groupId>org.owasp</groupId>
                    <artifactId>dependency-check-maven</artifactId>
                    <version>9.0.9</version>
                </dependency>
            </dependencies>          
            <executions>
                <execution>
                    <goals>
                        <goal>owasp-sonar-report</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```
The version of the `dependency-check-maven` plugin should be the same as the version used in your project. The `dependency-check-maven` plugin output format should be set to `JSON`. See the configuration below for an example:
```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>9.0.9</version>
            <configuration>
                <format>JSON</format>
            </configuration>
            <executions>
                <execution>
                    <id>owasp-dependency-check</id>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```
Now you can find the detected vulnerabilities on the _Issues_ tab of your project in SonarCloud. Th vulnerabilities will be qualified as **TBD**.  

## Java version
Java 11 and higher.

## License
This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE.md) file for details.


