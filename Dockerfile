# Multi-stage build. Pulls com.snowresorts:security-lib (+ contracts) from GitHub Packages,
# so pass a token at build time:
#   docker build --secret id=m2settings,src=$HOME/.m2/settings.xml -t auth-service .
# In CI the image is built after `mvn package`, so the jar already exists and the build
# stage is skipped when target/*.jar is present.
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY src/ src/
# settings.xml (with the `github` server) is mounted as a build secret for package access.
RUN --mount=type=secret,id=m2settings,target=/root/.m2/settings.xml,required=false \
    ./mvnw -B -ntp -DskipTests package

FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app
RUN useradd -r -u 1001 spring
COPY --from=build /workspace/target/*.jar app.jar
USER spring
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
