# TYST REST API

Exposes the core functionality of the TYST cryptographic provider over a REST
API.

Built with safe Rust and containerized, this gives you the full PQC crypto
agility of TYST in a tiny language agnostic OCI container.

## Quick start

Run the latest version

```text
podman run --rm --pull always --name tyst -P ghcr.io/mydriatech/tyst:latest
```

Show API

```text
curl -L 127.0.0.1:8084/openapi
```

## Intended use-case

By running this container in a side-car of your Kubernetes `Pod`, your
microservice app can discover and use of various cryptographic algorithms over a
`localhost` REST API.

This enables you to roll out new versions of this side-car to extend the crypto
capabilities of you microservice app without modifying the app.

This also ensures that you can develop your microservice in the most suitable
language as long as you can invoke a REST API.

## Performance considerations

Network calls bring overhead even over a `Pod`'s local network interface..

The REST API exposes `digest` and `mac` capabilities, but these will likely be
order of magnitudes slower than a native implementation due to the network call
overhead. → Mining bitcoins would be a bad idea, but hashing small chunks of
data from time to time would not.

For signatures and more advanced operations this is more likely to be less of a
concern. Please verify that this overhead is negligable for your intended use
case.

Also note that there is a limit in payload size. Streaming API endpoints for
very large payload are still on the roadmap.

## REST API documentation

Please see the generated OpenAPI documentation in `[openapi.json](openapi.json)`.

A small CLI is provided for re-generating this during development.

```text
# Run from the repository root
cargo run --bin openapi -- tyst-api-rest/openapi.json
```

## Building and Running

Building the container locally:

```text
# Run from the repository root
podman build --pull-always -t localhost/mydriatech/tyst:latest -f Containerfile .
```

Run the local container:

```text
podman run \
    --rm \
    --log-driver none \
    --name tyst-api-rest \
    --stop-signal SIGINT --stop-timeout 10 \
    --publish "127.0.0.1:8084:8084" \
    localhost/mydriatech/tyst:latest &
```

## Examples

Once you have it running on `127.0.0.1:8084`, you can proceed with running the
examples.

### Using Rust's `cargo`

You can find many examples in the `examples/` directory of the crate's GIT
repository:

```text
# You can run these from the repository root
cargo run --example digest_rest_example -- 127.0.0.1:8084
cargo run --example kem_rest_example    -- 127.0.0.1:8084
cargo run --example mac_rest_example    -- 127.0.0.1:8084
cargo run --example prng_rest_example   -- 127.0.0.1:8084
cargo run --example se_rest_example     -- 127.0.0.1:8084
```

### Using `curl`, `jq` and `base64`

Get OpenAPI documentation of the running version:

```text
curl 127.0.0.1:8084/openapi -L
```

Sign and verify a message using the NIST FIPS 204 algorithm ML-DSA-87:

```text
# (Optional) List available signature engines
curl http://127.0.0.1:8084/api/v1/ses -s -o -

# Generate a ML-DSA-87 key pair
eater=$(curl http://127.0.0.1:8084/api/v1/se/ML-DSA-87/keygen -d '' -s -o - -L)
private_key_b64="$(echo $eater | jq -r .private_key )"
public_key_b64="$(echo $eater | jq -r .public_key )"

# Sign
message_b64=$(echo "This will be signed." | base64)
eater=$(curl http://127.0.0.1:8084/api/v1/se/ML-DSA-87/sign \
    -d '{"private_key":"'${private_key_b64}'", "message":"'${message_b64}'"}' \
    --header "Content-type: application/json" \
    -s \
    -o -)
signature_b64=$(echo $eater | jq -r .signature )

# Verify signature (HTTP 204 means ok)
curl http://127.0.0.1:8084/api/v1/se/ML-DSA-87/verify \
    -d '{"public_key":"'${public_key_b64}'", "message":"'${message_b64}'", "signature":"'${signature_b64}'"}' \
    --header "Content-type: application/json" \
    -s \
    -o - -D -
```
