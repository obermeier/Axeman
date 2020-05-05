ARG PYTHON_VERSION=3.8

FROM python:${PYTHON_VERSION}

WORKDIR /usr/src/app

COPY . ./
RUN pip install --no-cache-dir -r requirements.txt
RUN python3 /usr/src/app/setup.py install

ENV OUTPUT_DIR=/tmp

ENTRYPOINT ["./axeman.sh"]
