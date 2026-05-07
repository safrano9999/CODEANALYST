#!/bin/bash
# CODEANALYST installer — delegates to the shared install template.
exec "$(dirname "$0")/../SCRIPTS/INSTALL/install_template.sh" "$@"
