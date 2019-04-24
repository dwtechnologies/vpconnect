.PHONY: new gen deploy-cf go-build docker-build docker-push clean

PWD          = $(shell pwd)
PROJECT      = vpconnect

OWNER       ?=
AWS_REGION  ?=
AWS_PROFILE ?=

# Check vars inside targets by calling "@:$(call check_var, VAR)"
check_var = $(strip $(foreach 1,$1,$(call __check_var,$1,$(strip $(value 2)))))
__check_var = $(if $(value $1),,$(error $1 variable not set))

new:
	@:$(call check_var, SERVICE)
	@:$(call check_var, ENVIRONMENT)
	@:$(call check_var, REGION)
	@:$(call check_var, PWD)
	@docker run \
		-v $(PWD):/src/vpconnect \
		-w /src/vpconnect/service-gen \
		golang:1.12-alpine3.9 \
		sh -c "apk --update add git && go run ./*.go new $(SERVICE) $(ENVIRONMENT) $(REGION)"


deploy: gen deploy-cf


gen:
	@:$(call check_var, SERVICE)
	@:$(call check_var, ENVIRONMENT)
	@:$(call check_var, PWD)
	@docker run \
		-e GOPATH=/go \
		-v $(PWD):/go/src/vpconnect \
		-w /go/src/vpconnect/service-gen \
		golang:1.12-alpine3.9 \
		sh -c "apk --update add git && go run ./*.go gen $(SERVICE) $(ENVIRONMENT)"


deploy-cf:
	@:$(call check_var, SERVICE)
	@:$(call check_var, ENVIRONMENT)
	@:$(call check_var, AWS_REGION)
	@:$(call check_var, AWS_PROFILE)
	@:$(call check_var, PROJECT)
	@:$(call check_var, OWNER)
	@aws cloudformation deploy \
		--template-file ./services/$(SERVICE)-$(ENVIRONMENT)/cf.yaml \
		--stack-name $(PROJECT)-$(SERVICE)-$(ENVIRONMENT) \
		--profile $(AWS_PROFILE) --region $(AWS_REGION) \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-fail-on-empty-changeset \
		--parameter-overrides \
			Name=$(SERVICE) \
			Environment=$(ENVIRONMENT) \
		--tags \
			Environment=$(ENVIRONMENT) \
			Project=$(PROJECT) \
			Owner=$(OWNER)
	@echo "\n\nService $(PROJECT)-$(SERVICE)-$(ENVIRONMENT) successfully deployed"


docker: go-build docker-build docker-push


go-build:
	@:$(call check_var, PWD)
	@mkdir -p ./build
	@docker run \
		-v $(PWD)/build:/build \
		-v $(PWD):/src/vpconnect \
		-w /src/vpconnect/vpconnect \
		golang:1.12-alpine3.9 \
		sh -c "apk --update add git && go build -o /build/vpconnect"
	@echo "\n\nbuild/vpconnect successfully built"


docker-build:
	docker build --tag vpconnect ./


docker-push: docker-build
	@:$(call check_var, AWS_REGION)
	@:$(call check_var, AWS_PROFILE)
	@:$(call check_var, REPO)
	$(eval HASH := $(shell docker inspect --format='{{.Id}}' vpconnect:latest | tr -d 'sha256:'))
	docker tag vpconnect:latest $(REPO)/vpconnect:$(HASH)
	@eval $(shell aws ecr get-login --no-include-email --profile $(AWS_PROFILE) --region $(AWS_REGION))
	docker push $(REPO)/vpconnect:$(HASH)
	@echo "\n\nDocker image pushed ($(REPO)/vpconnect:$(HASH))"


clean:
	rm -rf ./build
	@echo "\n\nProject cleaned"
