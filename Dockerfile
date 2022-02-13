FROM python:3.10 as base
ENV PIPE_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

FROM base as poetry
ENV POETRY_VERSION=1.1.13
RUN pip install "poetry==$POETRY_VERSION"
COPY poetry.lock pyproject.toml /app/
RUN poetry export -o requirements.txt

FROM base as build
COPY --from=poetry /app/requirements.txt /tmp/requirements.txt
RUN python -m venv .venv && \
    .venv/bin/pip install 'wheel==0.36.2' && \
    .venv/bin/pip install -r /tmp/requirements.txt

FROM python:3.10-slim
ENV PIPE_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH
CMD [ "python", "-m", "gcp_cloudflare_dyndns" ]
COPY --from=build /app/.venv /app/.venv
COPY . /app
WORKDIR /app/src
