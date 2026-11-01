PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest

.PHONY: install test demo serve

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	$(PYTEST) -q

demo:
	$(PYTHON) -m aegis demo

serve:
	$(PYTHON) -m aegis serve
