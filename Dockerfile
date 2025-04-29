# Use OpenJDK slim image directly
FROM openjdk:21-jdk-slim

LABEL maintainer="Aayush"

# Set working directory inside container
WORKDIR /app

# Copy target jar into container
COPY target/auth-service-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your app runs on
EXPOSE 8081

# Start the application
ENTRYPOINT ["java", "-jar", "app.jar"]
