FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# samba-ad-dc exists in bookworm and pulls the AD-capable samba build;
# samba-ad-provision carries the AD schema files samba-tool provision needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision krb5-user winbind smbclient \
 && rm -rf /var/lib/apt/lists/*

COPY seed/ /seed/
COPY provision.sh /provision.sh
RUN chmod +x /provision.sh

# Provisioning happens at container start (not image build) so the DC
# identity is tied to the running container hostname, not the image.
ENTRYPOINT ["/provision.sh"]
