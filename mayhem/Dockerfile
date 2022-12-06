FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake

COPY . /repo
WORKDIR /repo/tools/util
RUN gcc -o elf2cpe elf2cpe.c

FROM ubuntu:22.04 as package
COPY --from=builder /repo/tools/util/elf2cpe /
