
build:
	docker build -t dns-proxy .

start:
	docker run -d -p 127.0.0.1:53:53/udp --name dns-proxy --mount source=dns-proxy,target=/tmp --restart=always dns-proxy:latest

stop:
	docker container stop dns-proxy
	docker container prune -f

restart: stop start

deploy: build start

debug:
	docker run --entrypoint=sh -ti --mount source=dns-proxy,target=/tmp dns-proxy

push:
	docker tag dns-proxy chennequin/dns-proxy & docker push chennequin/dns-proxy

run:
	docker run -d -p 127.0.0.1:53:53/udp --name dns-proxy --mount source=dns-proxy,target=/tmp --restart=always chennequin/dns-proxy:latest

run:
	docker run -d -p 127.0.0.1:53:53/udp --name dns-proxy --mount source=dns-proxy,target=/tmp --restart=always chennequin/dns-proxy:latest

verify:
	cosign verify --key cosign.pub gcr.io/distroless/static-debian11
