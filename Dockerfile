FROM openjdk:8-jdk-alpine

COPY ./build/libs/authorize-endpoint-gateway-*.jar authorize-endpoint-gateway.jar

ENTRYPOINT ["java", "-jar", "/authorize-endpoint-gateway.jar"]