FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_VERSION=11.4.2
ARG GHIDRA_DATE=20250826
ARG CAPA_RULES_REF=master

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bash binutils curl file python3 python3-pip unzip yara \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt /app /samples /work \
    && curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && curl -fsSL "https://github.com/mandiant/capa-rules/archive/refs/heads/${CAPA_RULES_REF}.zip" -o /tmp/capa-rules.zip \
    && unzip -q /tmp/capa-rules.zip -d /opt \
    && mv "/opt/capa-rules-${CAPA_RULES_REF}" /opt/capa-rules \
    && rm /tmp/capa-rules.zip \
    && pip3 install --no-cache-dir flare-capa

ENV GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
ENV YARA_RULES_DIR=/rules
ENV CAPA_RULES_DIR=/opt/capa-rules
WORKDIR /app

CMD ["python3", "/app/app.py"]
