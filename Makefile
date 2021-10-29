all: csfix static-analysis test
	@echo "Done."

vendor: composer.json
	composer update
	touch vendor

.PHONY: csfix
csfix: vendor
	vendor/bin/php-cs-fixer fix --verbose

.PHONY: static-analysis
static-analysis: vendor
	vendor/bin/psalm

.PHONY: test
test: vendor
	php -d zend.assertions=1 vendor/bin/phpunit \
		--coverage-xml=coverage/coverage-xml \
		--coverage-html=coverage/html \
		--log-junit=coverage/junit.xml \
		${arg}
