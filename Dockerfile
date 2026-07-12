# Add this line to install the postgresql driver
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
