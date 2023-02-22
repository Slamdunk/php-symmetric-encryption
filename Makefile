CSFIX_PHP_BIN=PHP_CS_FIXER_IGNORE_ENV=1 php8.2
PHP_BIN=php8.2 -d zend.assertions=1 -d error_reporting=-1
COMPOSER_BIN=$(shell command -v composer)

SRCS := $(shell find ./src ./test -type f)

all: csfix static-analysis code-coverage
	@echo "Done."

vendor: composer.json
	$(PHP_BIN) $(COMPOSER_BIN) update
	$(PHP_BIN) $(COMPOSER_BIN) bump
	touch vendor

.PHONY: csfix
csfix: vendor
	$(CSFIX_PHP_BIN) vendor/bin/php-cs-fixer fix -v

.PHONY: static-analysis
static-analysis: vendor
	$(PHP_BIN) vendor/bin/phpstan analyse $(PHPSTAN_ARGS)

coverage/junit.xml: vendor $(SRCS) Makefile
	$(PHP_BIN) vendor/bin/phpunit \
		--coverage-xml=coverage/xml \
		--coverage-html=coverage/html \
		--log-junit=coverage/junit.xml \
		$(PHPUNIT_ARGS)

.PHONY: test
test: coverage/junit.xml

.PHONY: code-coverage
code-coverage: coverage/junit.xml
	$(PHP_BIN) vendor/bin/infection \
		--threads=$(shell nproc) \
		--coverage=coverage \
		--skip-initial-tests \
		$(INFECTION_ARGS)
