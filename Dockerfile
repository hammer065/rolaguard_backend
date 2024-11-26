# Use an official Python runtime as a parent image
FROM python:3.6-slim-buster

# Set the working directory to /iot_api
WORKDIR /iot_api

# copy requirements.txt separately, so the pip install doesn't happen again for every package
# this order change significantly speeds up building if we only have code changes
COPY ./requirements.txt ./

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip \
  && pip install --upgrade --trusted-host pypi.python.org --no-cache-dir --timeout 1900 -r requirements.txt \
  && find /usr/local/ \( -type d -a -name test -o -name tests \) -o \( -type f -a -name '*.pyc' -o -name '*.pyo' \) -delete \
  && apt-get clean autoclean \
  && apt-get autopurge -y \
  && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY . .

# Make port 5000 available to the world outside this container
# but needs to be published as 54107! TODO / TBD!!
EXPOSE 5000

# Define environment variable

# List of directories that Python should add to the sys.path directory list
ENV PYTHONPATH /iot_api/

# This prevents Python from writing out pyc files
ENV PYTHONDONTWRITEBYTECODE 1

# This keeps Python from buffering stdin/stdout
ENV PYTHONUNBUFFERED 1

WORKDIR /iot_api/iot_api

# Run flask when the container launches
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "iotservice:app", "-b", "0.0.0.0:5000"]
