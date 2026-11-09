PYTHON ?= python3
.DEFAULT_GOAL := check
.PHONY: check list replay
check:
	$(PYTHON) tools/verify.py
list:
	$(PYTHON) tools/run_offline.py --list
replay:
	@test -n "$(FIRMWARE_DIR)" || (echo 'Set FIRMWARE_DIR to hash-matching compressed firmware inputs'; exit 1)
	@test -n "$(OUTPUT)" || (echo 'Set OUTPUT to a new directory under work/'; exit 1)
	$(PYTHON) tools/run_offline.py --all --firmware-dir "$(FIRMWARE_DIR)" --output "$(OUTPUT)"
