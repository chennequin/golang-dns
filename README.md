# golang-dns

DNS server with a security focus which acts as a proxy and delegate UDP requests to well known DoH servers: Google, CloudFlare, Quad9.
- do not rely on the host root certificates. Uses known and validated root certificates only.
- do not rely on the host time. Make use of rough time instead.
- do not trust remote answers. Perform full DNSSEC validation. Modify on the fly incoming UDP packets and systematically ask for +dnssec.

work in progress...
