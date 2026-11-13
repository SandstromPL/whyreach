# whyreach as a container (INITIAL.md §3.5), built by goreleaser (dockers_v2)
# from the release binaries, which it puts at linux/<arch>/whyreach in the
# build context. FROM scratch: nothing is pulled, and the binary is static.
#
#   docker run --rm -i --pid host -v /var/run/docker.sock:/var/run/docker.sock \
#     ghcr.io/sandstrompl/whyreach:VERSION mcp serve
#
# --pid host lets whyreach read the containers' listening sockets through
# /proc/<pid>/net, as it does natively. whyreach's config is read from
# /config/whyreach/config.toml: mount yours there (read-only) to change it.
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/whyreach /whyreach
ENV XDG_CONFIG_HOME=/config XDG_STATE_HOME=/state XDG_DATA_HOME=/data
LABEL io.modelcontextprotocol.server.name="io.github.SandstromPL/whyreach"
ENTRYPOINT ["/whyreach"]
CMD ["mcp", "serve"]
