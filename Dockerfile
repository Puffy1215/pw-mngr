FROM python:latest
WORKDIR /vault
COPY ./manager.py .

EXPOSE 1234
CMD python3 ./manager.py