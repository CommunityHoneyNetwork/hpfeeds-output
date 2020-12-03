#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o errexit
set -o nounset
set -o pipefail


main () {
  python3 /opt/scripts/build_config.py
  python3 /opt/hpfeeds-output/bin/hpfeeds-output.py /opt/hpfeeds-output/output.json
}

main "$@"
