DOMAIN:=local

.PHONY: clean run all

all:

certs:
	mkdir -p certs
	cargo run --bin certgen -- --domain ${DOMAIN} --output-dir certs

run:
	$(MAKE) -C mkguest run

clean:
	rm -rf certs