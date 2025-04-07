FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY target/app-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "app.jar"]
