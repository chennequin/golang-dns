
docker:
	docker build -t udp-proxy .

start:
	docker run -d -p 127.0.0.1:53:53/udp --name udp-proxy --mount source=udp-proxy,target=/tmp --restart=always udp-proxy:latest

stop:
	docker container stop udp-proxy
	docker container prune -f

debug:
	docker run --entrypoint=sh -ti --mount source=udp-proxy,target=/tmp udp-proxy

verify:
	cosign verify --key cosign.pub gcr.io/distroless/static-debian11
