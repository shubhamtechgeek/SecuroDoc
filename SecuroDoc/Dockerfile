FROM eclipse-temurin:21-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the executable JAR file into the container at /app
COPY target/securodoc-api-1.0.jar /app/securodoc-api-1.0.jar

# Define build-time arguments for environment variables
ARG JWT_SECRET
ARG JWT_EXPIRATION

# Set environment variables
ENV JWT_SECRET=${JWT_SECRET}
ENV JWT_EXPIRATION=${JWT_EXPIRATION}

# Run the JAR file
ENTRYPOINT ["java", "-jar", "/app/securodoc-api-1.0.jar"]