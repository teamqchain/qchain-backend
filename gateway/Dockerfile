# =============================================================================
# QCHAIN GATEWAY — DOCKERFILE
# =============================================================================
#
# One small Nginx image: the single public entry point of the QChain API.
# Tailscale Funnel forwards https://<vm>.<tailnet>.ts.net to it on port 8090:
#
#     /api/       → the Go backend on localhost:3000 (the /api prefix is stripped)
#     /gw-health  → the gateway's own health check
#     /           → 302 redirect to QPortal, which is hosted on Vercel
#
# QPortal used to be compiled into this image (a Flutter build stage). Since
# November 2026 it is built and hosted by Vercel from the qchain-portal
# repository, so this image is Nginx plus one config file and builds in seconds.
#
# Build: bash gateway/docker-build.sh   (build context = this folder)
# The image and container keep the name qchain-web-gateway, so the CI rollback
# (qchain-web-gateway:previous) also works across the change.
# =============================================================================

FROM nginx:alpine

# Our routing config replaces Nginx's default server block.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Informational only: the container runs with --network host and listens on 8090.
EXPOSE 8090

# Docker marks the container healthy when /gw-health answers.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8090/gw-health || exit 1

CMD ["nginx", "-g", "daemon off;"]
