FROM maven:3.8.3-openjdk-17 AS builder

COPY ./src /var/backend/src
# COPY src/main/resources/sensor.csv /var/lib/backend/
COPY ./pom.xml /var/backend
WORKDIR /var/backend
RUN mvn package -Dmaven.test.skip=true
RUN java -Djarmode=layertools -jar /var/backend/target/sgx-deployment-framework-backend-0.0.1-SNAPSHOT.jar list
RUN java -Djarmode=layertools -jar /var/backend/target/sgx-deployment-framework-backend-0.0.1-SNAPSHOT.jar extract
#RUN ls -l /var/backend

FROM openjdk:17-jdk-slim

COPY --from=builder /var/backend/dependencies/ ./
COPY --from=builder /var/backend/snapshot-dependencies/ ./

RUN sleep 10
COPY --from=builder /var/backend/spring-boot-loader/ ./
COPY --from=builder /var/backend/application/ ./
EXPOSE 8082
# ENTRYPOINT ["java", "org.springframework.boot.loader.JarLauncher","-XX:+UseContainerSupport -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -XX:MaxRAMFraction=1 -Xms512m -Xmx512m -XX:+UseG1GC -XX:+UseSerialGC -Xss512k -XX:MaxRAM=72m"]
RUN apt-get update
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY ./sgx-deployment-framework-remote-attestation ./
SHELL ["/bin/bash", "-c"]
RUN yes | apt-get install autotools-dev automake libssl-dev wget net-tools supervisor curl
RUN yes yes | apt-get install build-essential git -y -q
RUN wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz
RUN tar xf openssl-1.1.1i.tar.gz
#RUN cd openssl-1.1.1i
RUN ./openssl-1.1.1i/config --prefix=/opt/openssl/1.1.1i --openssldir=/opt/openssl/1.1.1i
RUN make
RUN make install
RUN sed -i -e 's/\r$//' "./run-server"
RUN sed -i -e 's/\r$//' "./settings"
RUN sed -i -e 's/\r$//' "./policy"
RUN chmod 777 ./sp
RUN chmod 777 ./run-server
RUN chmod 777 ./run-client
RUN echo "/sample_libcrypto" > /etc/ld.so.conf.d/local.conf
RUN ldconfigx
RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/sample_libcrypto
EXPOSE 8085

CMD ["/usr/bin/supervisord"]