FROM python:3-alpine

RUN apk add --no-cache --virtual .build-tools build-base python3-dev libffi-dev openssl-dev
WORKDIR /opt/app

COPY . .

RUN pip install pipenv
RUN pipenv lock -r > requirements.txt
RUN pip install -r requirements.txt

RUN apk del .build-tools && apk add --no-cache bash

WORKDIR /opt/app/mysite

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
