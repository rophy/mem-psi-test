FROM busybox:1.37
COPY pressure.sh /pressure.sh
RUN chmod +x /pressure.sh
ENTRYPOINT ["/bin/sh", "/pressure.sh"]
