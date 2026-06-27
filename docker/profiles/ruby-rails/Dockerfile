# Ruby on Rails profile.
#
# The `ruby` runtime + Brakeman, the Rails-specific SAST. A SUPERSET of the
# `ruby` profile: same interpreter built the same way (ruby-build at the same
# pinned version), so the Ruby-level audit behaves identically, plus Brakeman
# for the Rails-shaped vulnerability classes (SQLi, XSS, mass-assignment,
# unsafe deserialization, command injection, SSRF, open redirect, CSRF gaps)
# that the generic semgrep pass does not match.
#
# Auto-selected for repos with config/application.rb (the canonical Rails boot
# file — see internal/worker/profile.go); also selectable via ?profile=ruby-rails.
#
# Built on demand by the worker (EnsureImage), tag
# scrutineer-profile-ruby-rails:<dockerfile-sha>, RUNNER_IMAGE via --build-arg.
#
#   docker build -t scrutineer-profile-ruby-rails \
#       -f docker/profiles/ruby-rails/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/ruby-rails

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

# Kept in lockstep with docker/profiles/ruby so the Rails runtime matches the
# base Ruby runtime exactly. Bump both together.
ARG RUBY_VERSION=3.4.9
ARG RUBY_BUILD_REF=v20260520
# Brakeman is pure Ruby; pin it like the rest of the image's tooling. Bump as
# new releases land.
ARG BRAKEMAN_VERSION=6.2.1

USER root
# Same toolchain as the ruby profile: ruby-build compiles CRuby from source, so
# it needs the C toolchain plus the headers Ruby links against. The toolchain
# also lets Bundler build a Rails app's native gem dependencies in-place.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        patch \
        git \
        libssl-dev \
        libyaml-dev \
        zlib1g-dev \
        libreadline-dev \
        libffi-dev \
        libgmp-dev \
        libncurses-dev \
        libgdbm-dev \
 && git clone --depth 1 --branch "${RUBY_BUILD_REF}" \
        https://github.com/rbenv/ruby-build.git /opt/ruby-build \
 && /opt/ruby-build/bin/ruby-build "${RUBY_VERSION}" /usr/local \
 && rm -rf /opt/ruby-build/.git /var/lib/apt/lists/* \
 && ruby --version \
 && bundle --version \
 && /opt/ruby-build/bin/ruby-build --version

# Install Brakeman into the default system gem dir (as root, before GEM_HOME is
# repointed below). The system gem dir is always on Gem.path, so the
# /usr/local/bin/brakeman wrapper resolves even once GEM_HOME points project
# gems at /work/.gem. --no-document keeps the image lean.
RUN gem install --no-document brakeman -v "${BRAKEMAN_VERSION}" \
 && brakeman --version

# Same as the ruby profile: project gems install into the writable,
# exec-capable /work mount rather than the root-owned image gem dir or the
# noexec /tmp fallback. /work/.gem sits outside /src so installed gems stay out
# of the scanned tree. Brakeman itself lives in the system gem dir and is
# unaffected by this. ruby-build is kept at /opt/ruby-build (on PATH) so a scan
# can install a Gemfile-pinned Ruby when the app's `ruby "x.y.z"` directive does
# not match 3.4 (Bundler enforces it, so install would otherwise fail).
ENV GEM_HOME=/work/.gem \
    PATH=/work/.gem/bin:/opt/ruby-build/bin:$PATH

USER runner
