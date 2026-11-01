# syntax=docker/dockerfile:1.7
# CYB691 ML image: ml-detector (scoring) and ml-train. Reuses the team's src/ml_detector.py features.
ARG BASE_IMAGE=python:3.12.8-slim-bookworm
FROM ${BASE_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY deploy/requirements/analytics.txt deploy/requirements/ml.txt /tmp/
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-compile -r /tmp/ml.txt

FROM ${BASE_IMAGE}
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="cyb691-ml" org.opencontainers.image.revision="${GIT_SHA}"
RUN groupadd --system --gid 10001 cyb691 && useradd --system --uid 10001 --gid 10001 --no-create-home cyb691 \
 && mkdir -p /objects && chown 10001:10001 /objects && chmod 0750 /objects
COPY --from=build /opt/venv /opt/venv
COPY --chown=root:root deploy/common /app/common
COPY --chown=root:root deploy/edge/__init__.py /app/edge/__init__.py
COPY --chown=root:root deploy/analytics /app/analytics
COPY --chown=root:root src/ml_detector.py src/database.py /app/src/
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CYB691_SRC_DIR=/app/src CYB691_GIT_SHA=${GIT_SHA} CYB691_OBJECT_ROOT=/objects MPLCONFIGDIR=/tmp
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["python", "-m", "analytics.jobs"]
CMD ["ml-score"]
