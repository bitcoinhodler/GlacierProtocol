# Only for running tests. Nothing else to make.

## Running tests:
# $ make                              -- Runs all tests
# $ make t/create-deposit-data.test   -- Runs a single test. Note there is no actual file by this name
#
## Writing tests:
# Create a t/foo.run bash script; make sure it is chmod +x.
# Create a matching t/foo.golden file; `touch t/foo.golden` is sufficient to start
# Run the test using `make t/foo.test`; it will fail since it doesn't match golden
# Manually check t/foo.out to ensure desired output
# $ mv t/foo.{out,golden}
# Ensure test passes now
# Commit!

SHELL := /bin/bash

all-tests := $(sort $(addsuffix .test, $(basename $(wildcard t/*.run))))

.PHONY : prereqs test all %.test clean

# Force parallel even when user was too lazy to type -j4
# with --jobs=4: real 0m30.574s
# with --jobs=8: real 0m20.733s
# with --jobs=12: real 0m19.104s
# with --jobs=16: real 0m18.530s
# with --jobs=100: real 0m18.327s but could exhaust system resources if we get enough tests
MAKEFLAGS += --jobs=16

# Run `make COVERAGE=1` to enable coverage.py coverage collection.
# Only works when running all tests.
ifdef COVERAGE
coverfile = $(addsuffix .cov, $(notdir $(basename $<)))
export GLACIERSCRIPT=env COVERAGE_FILE=../../coverage/$(coverfile) coverage run ../../glacierscript.py
else
export GLACIERSCRIPT=../../glacierscript.py
endif

# I need a unique port number for each bitcoind launched. Start with
# one higher than standard testnet port 18332, in case user already
# has a testnet daemon running.
compteur = 18333
# From https://stackoverflow.com/a/34156169/202201
# For target, given by the first parameter, set current *compteur* value.
# After issuing the rule, issue new value for being assigned to *compteur*.
define set_compteur
$(1): compteur = $(compteur) # Variable-assignment rule
compteur = $(shell echo $$(($(compteur)+1))) # Update variable's value
endef

$(foreach t,$(all-tests),$(eval $(call set_compteur, $(t))))


# Simulate actual conditions on Quarantined Laptop...bitcoind will
# normally not be running yet and ~/.bitcoin will not exist
define cleanup_bitcoind =
@mkdir -p $(BITCOIN_DATA_DIR)
@bitcoin-cli -testnet -rpcport=$(compteur) -datadir=$(BITCOIN_DATA_DIR) stop >/dev/null 2>&1 || exit 0
@if pgrep -f "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then echo Error: unable to stop bitcoind on port $(compteur); exit 1; fi
@bitcoin-cli -regtest -rpcport=$(compteur) -datadir=$(BITCOIN_DATA_DIR) stop >/dev/null 2>&1 || exit 0
@if pgrep -f "^bitcoind -regtest -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -regtest -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -regtest -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -regtest -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep -f "^bitcoind -regtest -rpcport=$(compteur)" >/dev/null; then echo Error: unable to stop bitcoind on port $(compteur); exit 1; fi
@sleep 1
@rm -rf $(BITCOIN_DATA_DIR)
endef

test : $(all-tests)
ifdef COVERAGE
	@cd coverage && \
	   coverage combine *.cov && \
	   coverage html \
	      --directory=../coverage-report \
	      "--omit=**/base58.py"
	@echo HTML coverage report generated in coverage-report/index.html
	#@rm -rf coverage
endif
	$(MAKE) clean
	@echo "Success, all tests passed."

clean:
	@(cd testrun && ../t/online-regtest-wallet.py stop)
	@rmdir testrun/bitcoin-data
	@rmdir testrun

OUTPUT = $(addsuffix .out, $(basename $<))
RUNDIR = testrun/$(notdir $@)
BITCOIN_DATA_DIR = testrun/bitcoin-data/$(compteur)
# Used only within the %.test rule:
GOLDEN_FILE = $(word 2, $?)

define test_recipe =
	$(cleanup_bitcoind)
	@mkdir -p $(BITCOIN_DATA_DIR) $(RUNDIR)
	cd $(RUNDIR) && ../../$< $(compteur) 2>&1 > ../../$(OUTPUT)
	@$(1) $(GOLDEN_FILE) $(OUTPUT) || \
	  (echo "Test $@ failed" && exit 1)
	@if [[ "$@" == *"withdrawal"* ]]; then \
	  if grep --word-regexp --quiet -- -regtest $<; then \
	    (cd testrun && ../t/online-regtest-wallet.py submit ../$(GOLDEN_FILE)); \
	  fi; \
	fi
	$(cleanup_bitcoind)
	@rm -rf $(RUNDIR)
	@rm $(OUTPUT)
endef


%.test : %.run %.golden glacierscript.py prereqs
	$(call test_recipe, diff -q)

%.test : %.run %.golden.re glacierscript.py prereqs
	$(call test_recipe, t/smart-diff.py)

prereqs:
	@which bitcoind > /dev/null || (echo 'Error: unable to find bitcoind'; exit 1)
	@which zbarimg > /dev/null || (echo 'Error: unable to find zbarimg (from package zbar-tools)'; exit 1)
	@which qrencode > /dev/null || (echo 'Error: unable to find qrencode'; exit 1)
ifdef COVERAGE
	@which coverage > /dev/null || (echo 'Error: unable to find coverage (Maybe "pip3 install coverage"?)'; exit 1)
	@rm -rf coverage
	@mkdir -p coverage
endif
	@mkdir -p testrun
	@(cd testrun && ../t/online-regtest-wallet.py start)
