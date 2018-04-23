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

ADD hsmsim-akka-0.0.1-SNAPSHOT.jar /root/hsm-emulator/hsm-emulator.jar
RUN bash -c 'touch /root/hsm-emulator/hsm-emulator.jar'
ADD install.sh /root/hsm-emulator/install.sh
RUN bash -c '/root/hsm-emulator/install.sh'

# lets default to the hsm-emulator dir so folks can more easily navigate to around the server install
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/root/hsm-emulator/hsm-emulator.jar"]

#CMD ["java","-jar", "-Dspring.config.location=/target/application.properties", "/home/hsm-emulator-1.0-SNAPSHOT.jar"]


