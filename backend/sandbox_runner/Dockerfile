FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1

# strace: trace target syscalls (same-uid ptrace, no CAP_SYS_PTRACE needed).
# coreutils: provides `timeout` for the per-process execution timeout.
RUN apk add --no-cache strace coreutils

RUN addgroup -g 10001 sandbox && adduser -D -u 10001 -G sandbox sandbox

RUN mkdir -p /analysis && chown -R sandbox:sandbox /analysis
WORKDIR /analysis

COPY sandbox.py /analysis/sandbox.py

USER sandbox:sandbox

ENTRYPOINT ["python", "/analysis/sandbox.py"]
CMD ["/analysis/input"]
