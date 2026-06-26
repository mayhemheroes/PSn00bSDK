# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds the PSn00bSDK host-tool fuzz harnesses on top of the
# org C/C++ base image. The base provides debian + clang/llvm + libFuzzer + the build-contract ENV;
# this only adds the per-commit build. Both targets are self-contained host tools, so no extra apt
# packages and no network are needed.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t psn00bsdk-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV (an empty value
# breaks clang). build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Declare WITHOUT a default so the base's SANITIZER_FLAGS ENV flows through unless overridden.
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run the functional tests at build time — a failing suite fails the image build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
