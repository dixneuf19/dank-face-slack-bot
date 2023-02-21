.PHONY: shell install install-dev dev build run push release release-multi deploy

PACKAGE_NAME=dank_face_slack_bot
DOCKER_REPOSITERY=dixneuf19
IMAGE_NAME=dank_face_slack_bot
IMAGE_TAG=$(shell git rev-parse --short HEAD)
DOCKER_IMAGE_PATH=$(DOCKER_REPOSITERY)/$(IMAGE_NAME):$(IMAGE_TAG)
APP_NAME=dank_face_slack_bot
KUBE_NAMESPACE=dank_face_bot

# Default target
all: dev

shell:
	poetry shell

install:
	poetry install --only main

install-dev:
	poetry install
	poetry run pre-commit install

dev:
	poetry run uvicorn ${PACKAGE_NAME}.main:api --reload

format:
	poetry run isort .
	poetry run black .

check-format:
	poetry run isort --check .
	poetry run black --check .
	poetry run ruff check .
	poetry run mypy .

test:
	poetry run pytest --cov=${PACKAGE_NAME} --cov-report=xml tests

build:
	docker build -t $(DOCKER_IMAGE_PATH) .

build-multi:
	docker buildx build --platform linux/amd64,linux/arm64,linux/386,linux/arm/v7 -t $(DOCKER_IMAGE_PATH) .

run: build
	docker run -p 8000:80 --env-file=.env $(DOCKER_IMAGE_PATH)

push:
	docker push $(DOCKER_IMAGE_PATH)

release: build push

release-multi:
	docker buildx build --platform linux/amd64,linux/arm64,linux/386,linux/arm/v7 -t $(DOCKER_IMAGE_PATH) . --push

deploy:
	kubectl apply -f $(APP_NAME).yaml

secret:
	kubectl create secret generic radio-france-api-token --from-env-file=.env

kube-credentials:
	NAMESPACE=${KUBE_NAMESPACE} ./scripts/generate-kubeconfig.sh
