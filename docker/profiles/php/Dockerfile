# PHP profile. Extends the scrutineer runner with a PHP interpreter so
# scans of Composer projects can audit or reproduce in-place.
#
# Built on demand by the worker; the image tag is content-addressed on
# this Dockerfile's sha so an edit invalidates the cache automatically.
#
#   docker build --build-arg RUNNER_IMAGE=<digest-pinned-runner> \
#     -t scrutineer-profile-php:<sha> docker/profiles/php

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

ARG PHP_VERSION=8.4.21-3+0~20260514.49+debian12~1.gbp45ccaf

USER root
# sury packages PHP 8.4 for bookworm; signed-by keyring, no apt-key.
# Extension parity with the prior Alpine pin (phar, openssl, tokenizer,
# fileinfo, iconv, dom, simplexml, xml, xmlwriter): php8.4-cli covers
# phar/openssl/tokenizer/fileinfo/iconv as builtins; php8.4-xml covers
# dom/simplexml/xml/xmlwriter; mbstring and curl are their own packages.
RUN install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://packages.sury.org/php/apt.gpg \
        -o /etc/apt/keyrings/sury-php.gpg \
 && chmod go+r /etc/apt/keyrings/sury-php.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" \
        > /etc/apt/sources.list.d/sury-php.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        php8.4-cli=${PHP_VERSION} \
        php8.4-mbstring=${PHP_VERSION} \
        php8.4-curl=${PHP_VERSION} \
        php8.4-xml=${PHP_VERSION} \
 && rm -rf /var/lib/apt/lists/*

USER runner
