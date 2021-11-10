#makefile for compiling the ocsp projects
#Author: Igor Khanenko

.DEFAULT_GOAL := default

#Terminal parameters
NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m
WARN_COLOR=\033[33;01m

PATFORM := $(shell uname -s)
ifeq ($(PATFORM),Linux)
	OS:=linux
else ifeq ($(PATFORM),Darwin)
	OS:=macos
else
    $(error Unsupported version of platform: [$(PLATFORM)])
endif

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGETALL=$(GOCMD) get -u
PROJECT_PATH=$(shell pwd)
PROJECT_GOROOT=$(shell $(GOCMD) env GOROOT)

# These will be provided to the target
#VERSION := `awk -F'["]' '/Version/{print $$2; exit;}' $(PWD)/ocsp.go`
VERSION := 0.1.0
BUILD := `git rev-parse HEAD`

# Use linker flags to provide version/build settings to the target
LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

.PHONY: default info clean build update-dep help

info:
	@echo "$(OK_COLOR)==> Project information:$(NO_COLOR)"
	@echo "$(OK_COLOR)OS:      $(OS)$(NO_COLOR)"
	@echo "$(OK_COLOR)PATH:    $(PROJECT_PATH)$(NO_COLOR)"
	@echo "$(OK_COLOR)GOROOT:  $(PROJECT_GOROOT)$(NO_COLOR)"
	@echo "$(OK_COLOR)VERSION: $(VERSION)$(NO_COLOR)"
	@echo "$(OK_COLOR)BUILD:   $(BUILD)$(NO_COLOR)"
	@echo "$(OK_COLOR)GO:      $(shell $(GOCMD) version)$(NO_COLOR)"

clean:
	@echo "$(WARN_COLOR)==> Cleaning builded project files:$(NO_COLOR)"
	@rm -rf bin/**

build: info clean
	@echo "Building application ocsp applications" ;\
	 mkdir -p $(PROJECT_PATH)/bin ;\
	 $(GOBUILD) -o $(PROJECT_PATH)/bin $(LDFLAGS) ;\
	 echo "OK";

test:
	@echo "$(OK_COLOR)==> Testing application$(NO_COLOR)";\
	 $(GOTEST) -v ./... ;\
	 echo "OK";

update-dep:
	@echo "$(OK_COLOR)==> Update dependencies: $(NO_COLOR)";\
	 $(GOGETALL);\
	 echo "OK";

help:
	@echo "$(WARN_COLOR)List of commands:" ;\
	 echo "> make clean        -- Remove all built applications from bin directory" ;\
	 echo "> make info         -- Show information about project environment. GO and DEP versions, etc." ;\
	 echo "> make build        -- Build applications and copy binary files to bin folder" ;\
	 echo "> make test         -- Run all tests for application " ;\
	 echo "> make update-dep   -- Update all dependencies for application $(NO_COLOR)" ;

default: help
