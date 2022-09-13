
build:
	docker build -t udp-proxy .

start:
	docker run -d -p 127.0.0.1:53:53/udp --name udp-proxy --mount source=udp-proxy,target=/tmp --restart=always udp-proxy:latest

stop:
	docker container stop udp-proxy
	docker container prune -f

restart: stop start

deploy: build restart

debug:
	docker run --entrypoint=sh -ti --mount source=udp-proxy,target=/tmp udp-proxy

push:
	docker tag udp-proxy chennequin/udp-proxy & docker push chennequin/udp-proxy

run:
	docker run -d -p 127.0.0.1:53:53/udp --name udp-proxy --mount source=udp-proxy,target=/tmp --restart=always chennequin/udp-proxy:latest

verify:
	cosign verify --key cosign.pub gcr.io/distroless/static-debian11
