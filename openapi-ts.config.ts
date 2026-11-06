import { defineConfig } from '@hey-api/openapi-ts';

// Generates from the PINNED spec in this repo, never from a URL, so a build is
// reproducible and offline and the diff shows which spec version produced it.
// Refresh with scripts/download-spec.sh.
//
// Only the operations a browser client calls, so what ships carries no wire code for
// the rest of the API.
export default defineConfig({
    input: './spec/openapi.yaml',
    output: {
        path: './src/generated',
    },
    parser: {
        filters: {
            operations: {
                include: [
                    'GET /{ip}',
                    'GET /myip',
                    'POST /batch',
                    'GET /api/v1/entitlement',
                    'GET /.well-known/oauth-authorization-server',
                    'POST /oauth/token',
                    'POST /oauth/revoke',
                ],
            },
        },
    },
    plugins: ['@hey-api/client-fetch'],
});
