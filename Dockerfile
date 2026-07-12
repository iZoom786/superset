# Add this line to install the postgresql driver
FROM apache/superset:latest
USER root
RUN pip install --upgrade pip && pip install psycopg2-binary
