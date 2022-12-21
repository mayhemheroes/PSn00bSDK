FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/tools/util
RUN gcc -o elf2cpe elf2cpe.c
RUN clang++ /repo/mayhem/fuzz_AddFileEntry.cpp /repo/tools/lzpack/filelist.cpp -fsanitize=fuzzer,address -I /repo/tools/lzpack/ -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/tools/util/elf2cpe /
COPY --from=builder /fuzz /fuzz_AddFileEntry
