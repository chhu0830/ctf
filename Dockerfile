FROM python:3.13.7-alpine

RUN pip install --upgrade pip
RUN pip install --upgrade mkdocs mkdocs-material

ENTRYPOINT ["mkdocs"]
