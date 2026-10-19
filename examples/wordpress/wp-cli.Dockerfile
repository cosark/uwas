FROM wordpress:cli-php8.3@sha256:f8aeb68164c6a04f5dcc91da30d8ffa096b0f7fafb7a65f144c2dd62587caca0

# The pinned upstream image ships vulnerable packages:
#   c-ares 1.34.6-r0              CVE-2026-33630
#   imagemagick-libs 7.1.2.24-r0  CVE-2026-53460, CVE-2026-53461
#   util-linux 2.42.1-r0          CVE-2026-53612…78410
#   libexpat 2.8.2/2.8.3-r0       CVE-2026-66046…93990
USER root
RUN apk add --no-cache --upgrade \
    "c-ares>=1.34.8-r0" \
    "imagemagick-libs>=7.1.2.27-r0" \
    "libexpat>=2.8.5-r0" \
    "util-linux>=2.42.3-r1"
USER www-data
