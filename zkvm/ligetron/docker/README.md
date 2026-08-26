# Ligetron (ligero-prover) images

Two images, both built from `ligero-prover` v1.5.0
(`6395bb105f259160b42654ec4e3592432b048126`).

`Dockerfile` is a **production trust anchor**: `packages/zkvm/src/backends/
ligetron-node.ts` runs `webgpu_prover` / `webgpu_verifier` out of it in docker
mode, and that verifier is the only path in the repository reporting
`kind: 'cryptographic'`. `Dockerfile.web` produces the emscripten prover the
browser backend loads into a Worker.

Every upstream input in both files is pinned by full commit SHA, image digest
or sha256, and every one of them is an overridable `ARG`. Build with the
defaults unless you are deliberately testing a different revision — an image
built with an overridden `ARG` is not `ligetron:v1.5.0`, whatever it is tagged.

## Native prover/verifier (docker mode)

```sh
docker build --platform linux/amd64 \
  -f zkvm/ligetron/docker/Dockerfile \
  -t ligetron:v1.5.0 zkvm/ligetron/docker
```

The build takes roughly an hour (Dawn and ligero-prover are both compiled from
source) and needs ~20 GB of disk. It asserts two things that used to fail only
at run time: that `WABT_REF` is a full commit SHA, and that the lavapipe ICD
manifest named by `VK_DRIVER_FILES` exists and loads.

Record the revisions the image actually contains alongside its digest:

```sh
docker image inspect ligetron:v1.5.0 \
  --format '{{json .Config.Labels}}'
docker image inspect ligetron:v1.5.0 --format '{{index .RepoDigests 0}}'
```

The three `io.zkdeal.*.commit` labels must match the `ARG` defaults in
`Dockerfile`; if they do not, the image was built with an override and is not
the reviewed build.

Configure the backend by tag (`packages/zkvm/src/backends/ligetron-node.ts`):

```
ligetronMode        = 'docker'
ligetronDockerImage = 'ligetron:v1.5.0'
ligetronGuest       = <path to zkdeal_stf_guest.wasm>
```

The backend runs `docker run --rm -e VK_DRIVER_FILES=... -e
VK_ICD_FILENAMES=... -v <jobDir>:/job -w /job <image>
/opt/ligero/build/<webgpu_prover|webgpu_verifier> <configJson>`. Two paths are
hardcoded on the consumer side and must not move in the image:
`/opt/ligero/build` (binaries) and `/opt/ligero/build/shader`.

## Web prover/verifier (browser mode)

```sh
docker build --platform linux/amd64 \
  -f zkvm/ligetron/docker/Dockerfile.web \
  -t ligetron-web:v1.5.0 zkvm/ligetron/docker
```

Outputs land in `/opt/ligero/build-web`. There is currently no script that
extracts them into the `ligetronProverJs` / `ligetronProverWasm` /
`ligetronProverData` artifacts that `packages/zkvm/src/backends/ligetron.ts`
sha256-pins; copy them out by hand and update the artifact pins.

## Notes

- Neither image is built by CI. A rebuild is a manual, reviewed operation.
- The shipped native image is the build stage itself (full toolchain, sources,
  root user). Slimming it to a runtime stage is a known follow-up; it would
  change the `/opt/ligero/build` layout the Node backend hardcodes, so it needs
  a coordinated change on both sides.
