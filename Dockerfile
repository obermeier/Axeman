ARG PYTHON_VERSION=3.8

FROM python:${PYTHON_VERSION}

RUN groupadd axeman
RUN useradd -m -g axeman axeman
USER axeman
WORKDIR /home/axeman

# Couldn't fint any other way..
RUN pip install virtualenv
RUN python3 -m virtualenv venv
ENV VIRTUAL_ENV /home/axeman/venv
ENV PATH /home/axeman/venv/bin:$PATH

COPY . ./
RUN pip install -r requirements.txt
RUN python3 setup.py install
ENV OUTPUT_DIR=/home/axeman/data

ENTRYPOINT ["./axeman.sh"]
