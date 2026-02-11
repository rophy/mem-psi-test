FROM gcc:14 AS builder
COPY dentry-generator.c /build/dentry-generator.c
RUN gcc -O2 -static -o /build/dentry-generator /build/dentry-generator.c

FROM busybox:1.37
COPY --from=builder /build/dentry-generator /dentry-generator
ENTRYPOINT ["/dentry-generator"]
CMD ["/tmp/dentry-flood", "--rate", "1000", "--mode", "negative"]
