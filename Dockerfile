FROM tomcat:8.5.35-jre8-alpine
LABEL maintainer="Kwaku Twumasi-Afriyie <kwaku@b1africa.com>"
COPY build/mysql-connector-java-5.1.47/mysql-connector-java-5.1.47-bin.jar /usr/local/tomcat/lib
COPY build/libs/fineract-provider.war /usr/local/tomcat/webapps
VOLUME /opt/tomcat/home /root
