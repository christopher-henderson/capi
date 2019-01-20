all:
	make nss
	make capi

capi: capi.go
	mkdir -p bin
	go build -o bin/capi capi.go

nss:
	mkdir -p nss
	cd nss; hg clone https://hg.mozilla.org/projects/nss
	cd nss; hg clone https://hg.mozilla.org/projects/nspr
	cd nss/nss/;./build.sh -v --opt
	mkdir -p bin
	mv nss/dist bin/

clean:
	rm -rf bin/*
