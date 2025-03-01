.PHONY: test
test:
	conftest verify -p .

.PHONY: fmt
fmt:
	opa fmt -w .
