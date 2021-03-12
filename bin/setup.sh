#!/bin/bash

set -e

python3 -mvenv --prompt s3-sysbackup pyenv
pyenv/bin/pip install -U pip
pyenv/bin/pip install -r $(dirname "$0")/../Development
