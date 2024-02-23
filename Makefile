#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

SHELL := env PATH=$(PATH) /bin/bash
PIP := pip3
PYTHON := python3

clean:
	find . -name "*.pyc" -o -name "__pycache__" | xargs rm -rf
	rm -rf .venv cdk.out

install_dev_dependencies:
	pip3 install -r requirements-dev.txt -q

format: install_dev_dependencies
	black lib eks_nitro_wallet app.py

lint: install_dev_dependencies
	-flake8 lib eks_nitro_wallet app.py

static_security_check: install_dev_dependencies
	-bandit -r lib eks_nitro_wallet app.py
	find  cdk.out/*template.json -exec cfn_nag_scan -i {} \;
