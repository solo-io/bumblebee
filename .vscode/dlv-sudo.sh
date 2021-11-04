#!/bin/sh

DLVDAP=$(which dlv-dap)

if [[ -x "${DLVDAP}" ]] ; then
	PATH="$GOPATH/bin/:$PATH"
fi

if [ "$DEBUG_AS_ROOT" = "true" ]; then
	exec sudo "$DLVDAP" --only-same-user=false "$@"
else
	exec "$DLVDAP" "$@"
fi