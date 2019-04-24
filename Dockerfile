FROM alpine:3.8

RUN apk --update add curl curl-dev iptables iptables-dev \
	ca-certificates iproute2 openssl openssl-dev build-base make


#############################################
# DOWNLOAD AND INSTALL OPENSWAN FROM SOURCE #
#############################################
RUN mkdir -p /tmp/src/strongswan
WORKDIR /tmp/strongswan

RUN echo "d449aa1936218a42e34c32494947308b  strongswan.tar.gz" > strongswan.tar.gz.md5 
RUN curl -L -o strongswan.tar.gz https://download.strongswan.org/strongswan-5.7.2.tar.gz
RUN md5sum -c strongswan.tar.gz.md5

RUN tar -C ./ --strip-components=1 -xzf strongswan.tar.gz

RUN ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib \
	--with-ipsecdir=/usr/lib/strongswan --enable-openssl --disable-md5 --disable-gmp \
	--disable-attr --disable-constraints --disable-curve25519 --disable-sshkey --disable-updown \
	--disable-cmac --disable-pem --disable-pki --disable-swanctl --disable-vici \
	--disable-pgp --disable-pkcs1 --disable-pkcs7 --disable-pkcs8 --disable-pkcs12 --disable-x509 \
	--disable-pki --disable-pubkey --disable-rc2 --disable-revocation --disable-scepclient \
	--disable-scripts --disable-xauth-generic --disable-des

RUN make && make install


#################################
# ADD VPCONNET BINARY & SCRIPTS #
#################################
ADD build/vpconnect /bin/vpconnect

WORKDIR /root

RUN apk del build-base curl-dev openssl-dev iptables-dev make
RUN rm -rf /var/cache/apk/* /tmp/*

CMD [ "/bin/vpconnect" ]
