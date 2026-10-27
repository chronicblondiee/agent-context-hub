FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS toolchain
COPY --from=ghcr.io/astral-sh/uv@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# Minimum supported native client runtime; no server dependencies or production access.
FROM python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377 AS hub-cli-smoke
ENV PYTHONDONTWRITEBYTECODE=1
COPY plugins/hub/bin/hub /source/plugins/hub/bin/hub
COPY scripts/package_hub_cli.sh /source/scripts/package_hub_cli.sh
COPY README.md /source/README.md
COPY LICENSE /source/LICENSE
COPY tests/__init__.py tests/test_hub_cli_package.py /source/tests/
WORKDIR /source
RUN --network=none python -m unittest tests.test_hub_cli_package

# Agent Context Hub images (scripts/hub.sh).
# Debian's SQLite (3.46) predates the required 3.51.3 WAL-reset fix; the stdlib sqlite3
# module links this build instead. SHA3-256 b6ced585…d9c4 per sqlite.org/download.html.
FROM toolchain AS sqlite-build
ADD --checksum=sha256:926ef8d3eab93fbf6e06011901273eec076b25594a4e1cdadd50c987f4f6d64e \
    https://sqlite.org/2026/sqlite-autoconf-3540100.tar.gz /sqlite.tar.gz
# Root package installation also supports builders in unprivileged containers.
RUN apt-get -o APT::Sandbox::User=root update \
    && apt-get -o APT::Sandbox::User=root install -y --no-install-recommends gcc libc6-dev make \
    && tar -xzf /sqlite.tar.gz -C /tmp && cd /tmp/sqlite-autoconf-3540100 \
    && CFLAGS="-O2 -DSQLITE_ENABLE_FTS5" ./configure --prefix=/usr/local --disable-static \
    && make -j"$(nproc)" && make install

# FastEmbed's ONNX mirror of sentence-transformers/all-MiniLM-L6-v2. Every artifact
# is tied to an immutable repository revision and checked before entering the image.
FROM toolchain AS hub-model
ARG MODEL_REVISION=d13954661f83248295ba75c1ed411eef3b7b936e
ADD --checksum=sha256:bbd7b466f6d58e646fdc2bd5fd67b2f5e93c0b687011bd4548c420f7bd46f0c5 https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/model.onnx /opt/models/minilm/model.onnx
ADD --checksum=sha256:851ca67100d372ca3ae031a6abd168f53489eebfd7d89523f35c5c9b4d372c3c https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/tokenizer.json /opt/models/minilm/tokenizer.json
ADD --checksum=sha256:1b4d8e2a3988377ed8b519a31d8d31025a25f1c5f8606998e8014111438efcd7 https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/config.json /opt/models/minilm/config.json
ADD --checksum=sha256:5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/special_tokens_map.json /opt/models/minilm/special_tokens_map.json
ADD --checksum=sha256:abda01c8c14c5151ae498aceb30db406d6b91242c394fd88d3b6fd5a63a101e6 https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/tokenizer_config.json /opt/models/minilm/tokenizer_config.json
ADD --checksum=sha256:07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3 https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx/resolve/${MODEL_REVISION}/vocab.txt /opt/models/minilm/vocab.txt
RUN chmod -R a+rX /opt/models

FROM toolchain AS hub-base
COPY --from=sqlite-build /usr/local/lib/libsqlite3.so* /usr/local/lib/
COPY --from=hub-model /opt/models /opt/models
RUN ldconfig && useradd -r -u 10001 app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY hub ./hub
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV HF_HUB_OFFLINE=1
ENV HUB_MODEL_DIR=/opt/models/minilm

# Offline migration/administration (migrate, bootstrap, backup, restore, admin-key).
FROM hub-base AS hub-operator
ARG SOURCE_REVISION=unknown
ENV HUB_SOURCE_REVISION=$SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
USER app

# Optional API-only NATS transport. It has no database mount.
FROM hub-base AS hub-federation
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
RUN uv sync --frozen --no-dev --group federation
USER app
CMD ["python", "-m", "hub.federation_transport"]

FROM hub-base AS hub-verification
RUN apt-get -o APT::Sandbox::User=root update \
    && apt-get -o APT::Sandbox::User=root install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN uv sync --frozen --all-groups
COPY tests ./tests
COPY scripts ./scripts
COPY . /source
USER app
CMD ["python", "-m", "unittest"]

FROM hub-base AS hub-runtime
ARG SOURCE_REVISION=unknown
ARG LOCK_SHA256=unknown
ARG SCHEMA_VERSION=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION \
      hub.lock.sha256=$LOCK_SHA256 \
      hub.schema.version=$SCHEMA_VERSION \
      hub.model.revision=d13954661f83248295ba75c1ed411eef3b7b936e
USER app
EXPOSE 8097
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8097/health/live')"]
CMD ["python", "-m", "hub"]
