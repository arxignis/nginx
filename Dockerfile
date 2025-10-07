ARG RESTY_IMAGE_BASE="alpine"
ARG RESTY_IMAGE_TAG="3.22"

FROM ${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG} AS openresty-builder

LABEL maintainer="Arxignis Team <hello@arxignis.com>"

# Set environment variables
ENV RESTY_VERSION="1.27.1.2"
ENV NGINX_VERSION="1.27.1"
ENV RESTY_OPENSSL_MAJOR_VERSION="3.4"
ENV RESTY_OPENSSL_VERSION="3.4.1"
ENV RESTY_OPENSSL_PATCH_VERSION="3.4.1"
ENV RESTY_OPENSSL_URL_BASE="https://github.com/openssl/openssl/releases/download/openssl-${RESTY_OPENSSL_VERSION}"
ENV RESTY_OPENSSL_SHA256="002a2d6b30b58bf4bea46c43bdd96365aaf8daa6c428782aa4feee06da197df3"
ENV GEOIP2_VERSION="3.4"
ENV NGX_JA4_MODULE_VERSION="1.3.1-beta"
ENV NGX_BROTLI_COMMIT_HASH="6e975bcb015f62e1f303054897783355e2a877dc"
ENV NGX_DYNAMIC_ETAG_VERSION="0.2.1"
ENV NGX_HTTP_AUTH_DIGEST_VERSION="1.0.0"
ENV MODSECURITY_NGINX_VERSION="1.0.4"
ENV MODSECURITY_NGINX_SHA256="6bdc7570911be884c1e43aaf85046137f9fde0cfa0dd4a55b853c81c45a13313"
ENV MODSECURITY_VERSION="3.0.14"
ENV MODSECURITY_SHA256="f7599057b35e67ab61764265daddf9ab03c35cee1e55527547afb073ce8f04e8"
ENV RESTY_PCRE_VERSION="10.44"
ENV RESTY_PCRE_SHA256="86b9cb0aa3bcb7994faa88018292bc704cdbb708e785f7c74352ff6ea7d3175b"
ENV RESTY_LUAROCKS_VERSION="3.12.2"
ENV RESTY_BALANCER_VERSION="0.05"
ENV RESTY_GPG_URL="https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz.asc"
ENV OPENTELEMETRY_CPP_CONTRIB_VERSION="0.1.1"


LABEL org.opencontainers.image.title="Arxignis custom build of the OpenResty"
LABEL org.opencontainers.image.documentation="https://github.com/arxignis/nginx"
LABEL org.opencontainers.image.source="https://github.com/arxignis/nginx"
LABEL org.opencontainers.image.vendor="Arxignis"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="${RESTY_VERSION}"
LABEL org.opencontainers.image.revision="${RESTY_VERSION}"
LABEL org.opencontainers.image.description="Arxignis custom build of the OpenResty"

WORKDIR /tmp

# Install build dependencies and runtime packages
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    pcre-dev \
    binutils \
    coreutils \
    curl \
    gd-dev \
    geoip-dev \
    libxslt-dev \
    linux-headers \
    make \
    perl-dev \
    readline-dev \
    zlib-dev \
    git \
    pkgconfig \
    m4 \
    autoconf \
    automake \
    libtool \
    sed \
    unzip \
    ca-certificates \
    gnupg \
    libmaxminddb-dev \
    brotli-dev \
    lmdb-dev \
    pcre-dev \
    cmake \
    && apk add --no-cache \
    bash \
    build-base \
    curl \
    libintl \
    linux-headers \
    make \
    musl \
    outils-md5 \
    perl \
    unzip \
    wget \
    gd \
    geoip \
    libgcc \
    libstdc++ \
    libxslt \
    tzdata \
    zlib \
    libmaxminddb \
    brotli \
    lmdb \
    pcre \
    wget \
    dumb-init \
    ca-certificates \
    patch \
    yajl \
    libxml2 \
    yaml-cpp \
    grpc-cpp \
    libprotobuf \
    abseil-cpp-crc-cpu-detect \
    abseil-cpp-vlog-config-internal \
    && curl -fSL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz" -o pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && echo "${RESTY_PCRE_SHA256}  pcre2-${RESTY_PCRE_VERSION}.tar.gz" | sha256sum -c \
    && tar xzf pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && cd /tmp/pcre2-${RESTY_PCRE_VERSION} \
    && CFLAGS="-g -O3" ./configure \
      --prefix=/usr/local/openresty/pcre2 \
      --libdir=/usr/local/openresty/pcre2/lib \
      --enable-jit --enable-pcre2grep-jit --disable-bsr-anycrlf --disable-coverage --disable-ebcdic --disable-fuzz-support \
      --disable-jit-sealloc --disable-never-backslash-C --enable-newline-is-lf --enable-pcre2-8 --enable-pcre2-16 --enable-pcre2-32 \
      --enable-pcre2grep-callout --enable-pcre2grep-callout-fork --disable-pcre2grep-libbz2 --disable-pcre2grep-libz --disable-pcre2test-libedit \
      --enable-percent-zt --disable-rebuild-chartables --enable-shared --disable-static --disable-silent-rules --enable-unicode --disable-valgrind \
    && CFLAGS="-g -O3" make -j$(nproc --all) \
    && CFLAGS="-g -O3" make -j$(nproc --all) install \
    && cd /tmp \
    && curl -fSL https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${MODSECURITY_VERSION}/modsecurity-v${MODSECURITY_VERSION}.tar.gz -o modsecurity-v${MODSECURITY_VERSION}.tar.gz \
    && echo "${MODSECURITY_SHA256}  modsecurity-v${MODSECURITY_VERSION}.tar.gz" | sha256sum -c \
    && tar xzf modsecurity-v${MODSECURITY_VERSION}.tar.gz \
    && cd /tmp/modsecurity-v${MODSECURITY_VERSION} \
    && ./build.sh \
    && ./configure --with-lmdb \
    && make \
    && make install \
    && rm -fr /tmp/modsecurity-v${MODSECURITY_VERSION} /usr/local/modsecurity/lib/libmodsecurity.a /usr/local/modsecurity/lib/libmodsecurity.la \
    && cd /tmp \
    && curl -fSL https://github.com/owasp-modsecurity/ModSecurity-nginx/releases/download/v${MODSECURITY_NGINX_VERSION}/ModSecurity-nginx-v${MODSECURITY_NGINX_VERSION}.tar.gz -o ModSecurity-nginx-v${MODSECURITY_NGINX_VERSION}.tar.gz \
    && echo "${MODSECURITY_NGINX_SHA256}  ModSecurity-nginx-v${MODSECURITY_NGINX_VERSION}.tar.gz" | sha256sum -c \
    && tar xzf ModSecurity-nginx-v${MODSECURITY_NGINX_VERSION}.tar.gz \
    && curl -fSL https://github.com/leev/ngx_http_geoip2_module/archive/refs/tags/${GEOIP2_VERSION}.tar.gz -o geoip2-nginx-module-${GEOIP2_VERSION}.tar.gz \
    && tar xzf geoip2-nginx-module-${GEOIP2_VERSION}.tar.gz \
    && git clone https://github.com/google/ngx_brotli \
    && cd ngx_brotli \
    && git reset --hard $NGX_BROTLI_COMMIT_HASH \
    && git submodule update --init \
    && cd /tmp \
    && curl -fsL https://github.com/dvershinin/ngx_dynamic_etag/archive/refs/tags/${NGX_DYNAMIC_ETAG_VERSION}.tar.gz -o ngx_dynamic_etag-${NGX_DYNAMIC_ETAG_VERSION}.tar.gz \
    && tar xzf ngx_dynamic_etag-${NGX_DYNAMIC_ETAG_VERSION}.tar.gz \
    && curl -fSL https://github.com/FoxIO-LLC/ja4-nginx-module/releases/download/v${NGX_JA4_MODULE_VERSION}/ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}.tar.gz -o ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}.tar.gz \
    && tar xzf ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}.tar.gz \
    && curl -fSL https://github.com/atomx/nginx-http-auth-digest/archive/refs/tags/v${NGX_HTTP_AUTH_DIGEST_VERSION}.tar.gz -o nginx-http-auth-digest-v${NGX_HTTP_AUTH_DIGEST_VERSION}.tar.gz \
    && tar xzf nginx-http-auth-digest-v${NGX_HTTP_AUTH_DIGEST_VERSION}.tar.gz \
    && curl -fSL "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && echo "${RESTY_OPENSSL_SHA256}  openssl-${RESTY_OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && cd openssl-${RESTY_OPENSSL_VERSION} \
    && curl -fSL https://raw.githubusercontent.com/openresty/openresty/refs/tags/v${RESTY_VERSION}/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch -o openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch \
    && patch -p1 < openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch \
    && patch -p1 < /tmp/ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}/patches/openssl.patch \
    && ./config \
      shared zlib -g \
      --prefix=/usr/local/openresty/openssl3 \
      --libdir=lib \
      -Wl,-rpath,/usr/local/openresty/openssl3/lib \
      enable-camellia enable-seed enable-rfc3779 enable-cms enable-md2 enable-rc5 \
      enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method enable-md2 enable-ktls enable-fips \
    && make -j$(nproc --all) \
    && make -j$(nproc --all) install_sw \
    && cd /tmp \
    && curl -fSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
    && tar xzf openresty-${RESTY_VERSION}.tar.gz \
    && cd /tmp/openresty-${RESTY_VERSION} \
    && patch -d bundle/nginx-${NGINX_VERSION}/ -p1 < /tmp/ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}/patches/nginx.patch \
    && ./configure -j$(nproc --all) \
      --with-pcre \
      --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include -I/usr/local/modsecurity/include' \
      --with-ld-opt='-L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -L/usr/local/modsecurity/lib -Wl,-rpath,/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib:/usr/local/modsecurity/lib' \
      --with-openssl=/tmp/openssl-${RESTY_OPENSSL_VERSION} \
      --with-compat \
      --with-http_auth_request_module \
      --with-http_geoip_module=dynamic \
      --with-http_gunzip_module \
      --with-http_gzip_static_module \
      --with-http_image_filter_module=dynamic \
      --with-http_mp4_module \
      --with-http_realip_module \
      --with-http_secure_link_module \
      --with-http_slice_module \
      --with-http_ssl_module \
      --with-http_stub_status_module \
      --with-http_sub_module \
      --with-http_v2_module \
      --with-http_v3_module \
      --with-http_xslt_module=dynamic \
      --with-ipv6 \
      --with-md5-asm \
      --with-sha1-asm \
      --with-stream \
      --with-stream_ssl_module \
      --with-stream_ssl_preread_module \
      --with-threads \
      --add-module=/tmp/ngx_http_geoip2_module-${GEOIP2_VERSION} \
      --add-module=/tmp/ngx_brotli \
      --add-module=/tmp/ngx_dynamic_etag-${NGX_DYNAMIC_ETAG_VERSION} \
      --add-module=/tmp/ja4-nginx-module-v${NGX_JA4_MODULE_VERSION}/src \
      --add-module=/tmp/ModSecurity-nginx-v${MODSECURITY_NGINX_VERSION} \
      --add-module=/tmp/nginx-http-auth-digest-${NGX_HTTP_AUTH_DIGEST_VERSION} \
      --without-mail_pop3_module \
      --without-mail_imap_module \
      --without-mail_smtp_module \
      --without-http_uwsgi_module \
        --without-http_rds_json_module \
      --without-http_rds_csv_module \
      --without-lua_rds_parser \
      --without-mail_pop3_module \
      --without-mail_imap_module \
      --without-mail_smtp_module \
      --with-http_addition_module \
      --with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT' \
      --with-pcre-jit \
      --user=www-data \
      --group=www-data \
      --http-log-path=/var/log/nginx/access.log \
      --error-log-path=/var/log/nginx/error.log \
      --lock-path=/var/lock/nginx.lock \
      --pid-path=/run/nginx.pid \
      --http-client-body-temp-path=/var/lib/nginx/body \
      --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
      --http-proxy-temp-path=/var/lib/nginx/proxy \
      --http-scgi-temp-path=/var/lib/nginx/scgi \
      --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
      --conf-path=/etc/nginx/nginx.conf \
    && make -j$(nproc --all) \
    && make -j$(nproc --all) install \
    && cd /tmp \
    && curl -fSL https://github.com/open-telemetry/opentelemetry-cpp-contrib/releases/download/nginx%2Fv${OPENTELEMETRY_CPP_CONTRIB_VERSION}/otel_ngx_module-alpine-3.20-${NGINX_VERSION}.so -o /usr/local/openresty/nginx/modules/otel_ngx_module.so \
    && curl -fSL https://github.com/openresty/lua-resty-balancer/archive/refs/tags/v${RESTY_BALANCER_VERSION}.tar.gz -o lua-resty-balancer-${RESTY_BALANCER_VERSION}.tar.gz \
    && tar xzf lua-resty-balancer-${RESTY_BALANCER_VERSION}.tar.gz \
    && cd lua-resty-balancer-${RESTY_BALANCER_VERSION} \
    && make LUA_INCLUDE_DIR=/usr/local/openresty/luajit/include \
    && make install \
      LUA_INCLUDE_DIR=/usr/local/openresty/luajit/include \
      LUA_LIB_DIR=/usr/local/openresty/lualib \
    && cd /tmp \
    && curl -fSL https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install \
    && cd /tmp \
    && apk del .build-deps \
    && mkdir -p /var/run/openresty \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && rm -rf /tmp/* \
    && mkdir -p /var/lib/nginx \
    && apk add --no-cache --virtual .gettext gettext \
    && mv /usr/bin/envsubst /tmp/ \
    && apk del .gettext \
    && mv /tmp/envsubst /usr/local/bin/ \
    && adduser -S -D -H -u 101 -h /usr/local/nginx -s /sbin/nologin -G www-data -g www-data www-data \
    && for dir in \
      /etc/nginx \
      /usr/local/nginx \
      /opt/modsecurity/var/log \
      /opt/modsecurity/var/upload \
      /opt/modsecurity/var/audit \
      /var/log/audit \
      /var/log/nginx \
      /var/lib/nginx/body \
      /var/lib/nginx/fastcgi \
      /var/lib/nginx/proxy \
      /var/lib/nginx/scgi \
      /var/lib/nginx/uwsgi \
      /var/lock \
      /run; do \
        mkdir -p ${dir}; \
        chown -R www-data:www-data ${dir}; \
        chmod 755 ${dir}; \
    done

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

# Add LuaRocks paths
ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"

ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"

CMD ["/usr/local/openresty/nginx/sbin/nginx", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
STOPSIGNAL SIGQUIT

FROM openresty-builder AS runtime
ENV ARXIGNIS_VERSION="1.5-0"

WORKDIR /etc/nginx

RUN apk --no-cache add git \
    && luarocks install lua-resty-arxignis ${ARXIGNIS_VERSION}
