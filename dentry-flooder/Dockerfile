FROM busybox:1.37
COPY flood.sh /flood.sh
RUN chmod +x /flood.sh
ENTRYPOINT ["/bin/sh", "/flood.sh"]
