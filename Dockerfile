FROM openjdk:11.0.12-jre-slim-buster
LABEL base-image="openjdk:11.0.12-jre-slim-buster" \
      java-version="11.0.12" \
      purpose="Hello World with SSL, Java and Dockerfile" 
MAINTAINER Indrani Dey <idey at red hat> 
WORKDIR /deployments 
COPY target/*.jar app.jar 
USER 185 
EXPOSE 8443 
CMD ["java", "-jar","app.jar"]
