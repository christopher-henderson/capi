clean:
	-docker stop capi
	-docker rm capi
	-docker rmi capi
	-docker image prune -f
	-docker image prune -f --filter label=stage=intermediate

build:
	docker build --rm -t capi:latest .
	docker image prune -f
	docker image prune -f --filter label=stage=intermediate

run:
	./run.sh