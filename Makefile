BUILD_DIR := build
MAIN_FILE := cmd/main.go
IMAGE_NAME := kai-take-home
PORT := 80

.PHONY: all
all: build

# Run tests
.PHONY: test
test:
	go test ./... -coverpkg=./... -coverprofile=/tmp/cover.out
	go tool cover -html=/tmp/cover.out

.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/server $(MAIN_FILE)

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

.PHONY: run
run:
	go run $(MAIN_FILE)

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE_NAME) .

.PHONY: docker-run
docker-run: docker-build
	docker run --rm -p $(PORT):8080 $(IMAGE_NAME)

.PHONY: docker-clean
docker-clean:
	docker rmi $(IMAGE_NAME)
