.PHONY: new gen deploy-cf go-build docker-build docker-push clean

PWD     = $(shell pwd)
PROJECT = vpconnect

# Check vars inside targets by calling "@:$(call check_var, VAR)"
check_var = $(strip $(foreach 1,$1,$(call __check_var,$1,$(strip $(value 2)))))
__check_var = $(if $(value $1),,$(error $1 variable not set))

# Tags var will append tags with --tags if tags is not empty.
# Should be claled with @$(call tags_var, TAGS)
tags_var = $(strip $(foreach 1,$1,$(call __tags_var,$1,$(strip $(value 2)))))
__tags_var = $(if $(value $1),$(eval TAGS=--tags $(TAGS)),)

new:
	@:$(call check_var, SERVICE)
	@:$(call check_var, PWD)
	@docker run \
		-v $(PWD):/src/vpconnect \
		-w /src/vpconnect/service-gen \
		golang:1.12-alpine3.10 \
		sh -c "apk --update add git && go run ./*.go new $(SERVICE)"


deploy: gen deploy-cf


gen:
	@:$(call check_var, SERVICE)
	@:$(call check_var, PWD)
	@docker run \
		-v $(PWD):/src/vpconnect \
		-w /src/vpconnect/service-gen \
		golang:1.12-alpine3.10 \
		sh -c "apk --update add git && go run ./*.go gen $(SERVICE)"


deploy-cf:
	@:$(call check_var, SERVICE)
	@:$(call check_var, ENVIRONMENT)
	@:$(call check_var, PROJECT)
	@:$(call check_var, OWNER)
	@$(call tags_var, TAGS)
	@aws cloudformation deploy \
		--template-file ./services/$(SERVICE)/cf.yaml \
		--stack-name $(PROJECT)-$(SERVICE) \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-fail-on-empty-changeset \
		--parameter-overrides \
			Name=$(SERVICE) \
		$(TAGS)
	@echo "Service $(PROJECT)-$(SERVICE) successfully deployed"


docker: go-build docker-build docker-push


go-build:
	@:$(call check_var, PWD)
	@mkdir -p ./build
	@docker run \
		-v $(PWD)/build:/build \
		-v $(PWD):/src/vpconnect \
		-w /src/vpconnect/vpconnect \
		golang:1.12-alpine3.10 \
		sh -c "apk --update add git && go build -ldflags='-s -w' -o /build/vpconnect"
	@echo "vpconnect successfully built"


docker-build:
	docker build --tag vpconnect ./


docker-push: docker-build
	@:$(call check_var, REPO)
	$(eval HASH := $(shell docker inspect --format='{{.Id}}' vpconnect:latest | tr -d 'sha256:'))
	docker tag vpconnect:latest $(REPO)/vpconnect:$(HASH)
	@eval $(shell aws ecr get-login --no-include-email)
	docker push $(REPO)/vpconnect:$(HASH)
	@echo "Docker image pushed ($(REPO)/vpconnect:$(HASH))"


clean:
	rm -rf ./build
	@echo "Project cleaned"
