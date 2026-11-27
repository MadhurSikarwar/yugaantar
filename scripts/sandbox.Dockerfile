# Image for scripts/sandbox_docker.sh: the documented judging runtime (Python 3.12 + pqcrypto==0.4.0).
# The submission is NOT baked in: it is mounted read-only at run time. No network is needed after the build.
# If the build of pqcrypto fails on the slim image, change the base to `python:3.12`.
FROM python:3.12-slim
RUN pip install --no-cache-dir pqcrypto==0.4.0
WORKDIR /tmp
