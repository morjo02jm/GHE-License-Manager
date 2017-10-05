FROM isl-dsdc.ca.com:5005/tomcat:8-jre8

RUN apt-get update && apt-get install nano

#create application path, so we can CHOWN it later
ENV APP_ROOT=/usr/local/tomcat
ENV HOME=${APP_ROOT}
# RUN mkdir -p ${APP_ROOT}

RUN /bin/rm -rf /usr/local/tomcat/webapps/docs
RUN /bin/rm -rf /usr/local/tomcat/webapps/examples

ADD http://isl-dsdc.ca.com/artifactory/maven-integration-local/com/ca/tools/ghelp.tools.ca.com/0.0.1-SNAPSHOT/ghelp.tools.ca.com-0.0.1-SNAPSHOT.war /usr/local/tomcat/webapps/ghe.war
ADD http://isl-dsdc.ca.com/artifactory/generic-integration-local/GitHub%20Enterprise/License%20Sharing%20Policy/unsuspend /usr/local/tomcat/bin/unsuspend

#add nss for openshift passwd modifications
#the required libnss-wrapper is not in the stable repository
ADD docker_add_files/unstable.pref /etc/apt/preferences.d/unstable.pref
ADD docker_add_files/unstable.list /etc/apt/sources.list.d/unstable.list
RUN apt-get update && apt-get install -y -t unstable libnss-wrapper
RUN rm -rf /etc/apt/preferences.d/unstable.pref && rm -rf /etc/apt/sources.list.d/unstable.list

# install gettext for envsubst, additional tools needed for nss
RUN apt-get update && apt-get install -y gettext

# # copy passwd template file for use with OpenShift dynamically created user via nss-wrapper
COPY docker_add_files/passwd.template /tmp/passwd.template

RUN chmod +x /usr/local/tomcat/bin/unsuspend

# RUN groupadd tomcat \
#     && useradd tomcat 

RUN chgrp -R 0 ${APP_ROOT} \
    && chmod -R g=u ${APP_ROOT} /etc/passwd

#CMD ["catalina.sh", "run"]
ENTRYPOINT /bin/sh -c "export USER_ID=$(id -u) \
           && export GROUP_ID=$(id -g) \
           && envsubst < /tmp/passwd.template > /tmp/passwd \
           && export LD_PRELOAD=libnss_wrapper.so \
           && export NSS_WRAPPER_PASSWD=/tmp/passwd \
           && export NSS_WRAPPER_GROUP=/etc/group \
           && echo GitHub License Sharing ##buildnum## \
           && catalina.sh run"


#&& cp /usr/local/tomcat/webapps2/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml \
           

# FROM isl-dsdc.ca.com:5005/node:7.7.2-slim

# #The node application uses port 4000
# EXPOSE 4000

# #create application path, so we can CHOWN it later
# ENV APP_ROOT=/app
# ENV HOME=${APP_ROOT}
# RUN mkdir -p ${APP_ROOT}

# WORKDIR /app

# #install necessary packages for Yarn
# COPY . .
# RUN apt-get update && \
#     apt-get install -y apt-transport-https curl sudo
# RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
# RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
# RUN apt-get update && apt-get install -y yarn

# #add nss for openshift passwd modifications
# #the required libnss-wrapper is not in the stable repository
# ADD docker_add_files/unstable.pref /etc/apt/preferences.d/unstable.pref
# ADD docker_add_files/unstable.list /etc/apt/sources.list.d/unstable.list
# RUN apt-get update && apt-get install -y -t unstable libnss-wrapper
# RUN rm -rf /etc/apt/preferences.d/unstable.pref && rm -rf /etc/apt/sources.list.d/unstable.list

# # install gettext for envsubst, additional tools needed for nss
# RUN apt-get update && apt-get install -y gettext

# # copy passwd template file for use with OpenShift dynamically created user via nss-wrapper
# COPY docker_add_files/passwd.template /tmp/passwd.template

# RUN ["yarn", "install"]

# #set the necessary permissions for OpenShift dynamic user
# RUN chgrp -R 0 ${APP_ROOT} \
#     && chmod -R g=u ${APP_ROOT} /etc/passwd

# ENTRYPOINT /bin/sh -c "export USER_ID=$(id -u) \
#            && export GROUP_ID=$(id -g) \
#            && envsubst < /tmp/passwd.template > /tmp/passwd \
#            && export LD_PRELOAD=libnss_wrapper.so \
#            && export NSS_WRAPPER_PASSWD=/tmp/passwd \
#            && export NSS_WRAPPER_GROUP=/etc/group \
#            && echo github-events-master ##buildnum## \
#            && yarn start"
