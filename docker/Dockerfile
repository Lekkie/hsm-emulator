FROM centos:latest
FROM java:8
MAINTAINER Lekan Omotayo <lekkie.aydot@gmail.com>

ADD VERSION .

ARG HSM_EMULATOR_VERSION=1.0-SNAPSHOT
# Update CentOS 7
#RUN yum update -y && yum upgrade -y
# Install packages
#RUN yum install -y unzip wget curl git
# Install EPEL Repository
#RUN yum install -y epel-release
# Clean CentOS 7
#RUN yum clean all

EXPOSE 1501

VOLUME /tmp
#WORKDIR /root/hsm-emulator

ADD hsmsim-akka-0.0.1-SNAPSHOT-jar-with-dependencies.jar /root/hsm-emulator/hsm-emulator.jar

#ADD lib/akka-actor.jar /root/hsm-emulator/lib/akka-actor.jar
#ADD lib/bcprov-ext-jdk16-1.46.jar /root/hsm-emulator/lib/bcprov-ext-jdk16-1.46.jar
#ADD lib/config-1.0.2.jar /root/hsm-emulator/lib/config-1.0.2.jar
#ADD lib/protobuf-java-3.5.1.jar /root/hsm-emulator/lib/protobuf-java-3.5.1.jar
#ADD lib/scala-library-2.10.2.jar /root/hsm-emulator/lib/scala-library-2.10.2.jar

RUN bash -c 'touch /root/hsm-emulator/hsm-emulator.jar'

#RUN bash -c 'touch /root/hsm-emulator/lib/akka-actor.jar'
#RUN bash -c 'touch /root/hsm-emulator/lib/bcprov-ext-jdk16-1.46.jar'
#RUN bash -c 'touch /root/hsm-emulator/lib/config-1.0.2.jar'
#RUN bash -c 'touch /root/hsm-emulator/lib/protobuf-java-3.5.1.jar'
#RUN bash -c 'touch /root/hsm-emulator/lib/scala-library-2.10.2.jar'

ADD install.sh /root/hsm-emulator/install.sh
RUN bash -c '/root/hsm-emulator/install.sh'

# lets default to the hsm-emulator dir so folks can more easily navigate to around the server install
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/root/hsm-emulator/hsm-emulator.jar"]
#ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-cp", "/root/hsm-emulator/hsm-emulator.jar,/root/hsm-emulator/lib/*", "org.leachbj.hsmsim.Sim"]

#CMD ["java","-jar", "-Dspring.config.location=/target/application.properties", "/home/hsm-emulator-1.0-SNAPSHOT.jar"]


