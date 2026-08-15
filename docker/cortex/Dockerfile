FROM thehiveproject/cortex:latest

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-requests libmagic1 \
    && ln -s /usr/bin/python3 /usr/local/bin/python \
    && pip3 install --break-system-packages --no-cache-dir \
        cortexutils \
        validators \
        idna \
        tld \
        sqlalchemy \
        psycopg2-binary \
        dnspython \
        python-dateutil \
        pytz \
        diskcache \
        checkdmarc \
        python-magic \
        filetype \
        vt-py \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
