#!/bin/bash

# Publishes the package to npm from inside the official Node image, so a release
# needs nothing installed locally beyond docker and works identically on any
# machine. The release workflow does the same steps on a tag; this is the manual
# path for a first release or when Actions is not an option. The browser test
# needs a Chromium the image lacks, so CI runs it before any tag.
#
#   NPM_TOKEN=... ./scripts/publish.sh            # publish
#   NPM_TOKEN=... DRY_RUN=1 ./scripts/publish.sh  # rehearse
#
# The token must be able to publish WITHOUT an interactive OTP: either a classic
# automation token, or a granular access token with the 2FA bypass enabled.
# Otherwise npm answers 403 "Two-factor authentication or granular access token
# with bypass 2fa enabled is required to publish packages."
#
# No --provenance here: provenance is an attestation that a CI system built the
# artifact, and it needs OIDC credentials a laptop does not have. Releases made
# through the workflow get it; this path deliberately does not claim it.

set -euo pipefail

cd "$(dirname "$0")/.."

: "${NPM_TOKEN:?set NPM_TOKEN to a token that can publish without an OTP}"
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"
DRY_RUN="${DRY_RUN:-}"

publish_args="--no-git-checks"
if [ -n "$DRY_RUN" ] ; then
    publish_args="$publish_args --dry-run"
fi

# The anonymous volume gives the container its OWN node_modules. Without it the
# bind mount exposes the host's, which pnpm then wants to purge (it was
# installed for a different store) - and with no TTY to confirm, it aborts.
# Worse, a purge that DID go ahead would delete the working tree's dependencies
# out from under whoever is using them.
#
# dist deliberately does NOT get one: it is a mount point rather than a
# directory, so the build's `rm -rf dist` fails on it with "Resource busy".
docker run --rm \
    -v "$PWD:/w" -v /w/node_modules \
    -w /w \
    -e NPM_TOKEN="$NPM_TOKEN" \
    -e CI=true \
    -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    "$NODE_IMAGE" sh -euc "
        corepack enable
        npm config set //registry.npmjs.org/:_authToken \"\$NPM_TOKEN\"
        pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store
        pnpm run lint
        pnpm run test
        pnpm publish $publish_args
    "
