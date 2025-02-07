FROM python:3.10

ADD app.py .

RUN pip install flask
RUN pip install pandas
RUN pip install jwt

CMD ["python", "./app.py"]