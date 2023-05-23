# spring-boot-scheduler

Pre-req:
***Create a certificate named test.p12:
keytool -genkeypair -alias test -keyalg RSA -keysize 4096 -storetype PKCS12 -keystore test.p12 -validity 3650 -storepass password

***Place the certificate under src/main/resources/test.p12

***Add the following in src/main/resources/application.properties file
server.port=8443
server.ssl.enabled=true
server.ssl.key-alias=test
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=${PK12_PASSWORD}
server.ssl.key-store=file:${PK12_LOCATION}

***pre-deploy:
oc create secret generic spring-boot-jks-file --from-file test.p12
oc create secret generic spring-boot-secrets --from-literal=JKS_PASSWORD=password --from-literal=JKS_LOCATION=/tmp/jks/test.p12


***Build:
oc new-build --strategy docker --binary --docker-image openjdk:11.0.12-jre-slim-buster --name spring-boot-jks
oc start-build spring-boot-jks --from-dir . --follow

***Deploy
oc new-app --name=spring-boot-jks --image-stream=spring-boot-jks:latest

***post deploy
oc set volume deployment/spring-boot-jks --add --name=spring-boot-jks-mnt --secret-name=spring-boot-jks-file --mount-path=/tmp/jks/
oc set env deployment/spring-boot-jks --from=secret/spring-boot-secrets

***Create Route
oc create route passthrough  --service spring-boot-jks --port=8443

**Test
oc get route
curl -kv https://<route>/welcome/message