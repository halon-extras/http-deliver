FROM --platform=linux/amd64 centos:7
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

RUN yum update -y && yum install -y epel-release

RUN echo "[halon]" >> /etc/yum.repos.d/Halon.repo
RUN echo "name=Halon repository" >> /etc/yum.repos.d/Halon.repo
RUN echo "baseurl=https://${HALON_REPO_USER}:${HALON_REPO_PASS}@repo.halon.io/dists/rhel7/amd64/stable" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgkey=https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc" >> /etc/yum.repos.d/Halon.repo
RUN echo "enabled=1" >> /etc/yum.repos.d/Halon.repo
RUN yum install -y halon-6.3.0

RUN yum install -y centos-release-scl

RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

RUN yum install -y devtoolset-8

SHELL ["/usr/bin/scl", "enable", "devtoolset-8"]

COPY scl_enable /usr/bin/scl_enable
ENV BASH_ENV="/usr/bin/scl_enable" \
    ENV="/usr/bin/scl_enable" \
    PROMPT_COMMAND=". /usr/bin/scl_enable"

RUN yum install -y cmake3 make gcc-c++ rpm-build
RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://www.openssl.org/source/openssl-1.1.1n.tar.gz \
    && tar -xzvf openssl-1.1.1n.tar.gz && cd openssl-1.1.1n \
    && ./config \
    && make && make install
RUN cd /tmp/halon \
    && curl -O -L https://github.com/curl/curl/releases/download/curl-7_80_0/curl-7.80.0.tar.gz \
    && tar -zxvf curl-7.80.0.tar.gz && cd curl-7.80.0 \
    && LD_LIBRARY_PATH=/usr/local/lib64 ./configure --without-ssl --without-ldap \
    && make && make install \
    && cp /usr/local/lib/pkgconfig/libcurl.pc /usr/lib64/pkgconfig/ \
    && rm /usr/local/bin/curl
RUN rm -rf /tmp/halon
RUN echo -n "CENTOS7" > /OSRELEASE.txt

COPY build.sh /build.sh
CMD ["/build.sh"]
