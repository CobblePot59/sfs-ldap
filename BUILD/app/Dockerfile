FROM python:slim-buster

WORKDIR /opt/sfs/sources

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends gcc libsasl2-dev libldap2-dev && \
    python3 -m pip install --no-cache-dir gunicorn flask flask-sqlalchemy flask-ldap3-login flask-dropzone hashids aioflask bcrypt asgiref flask-toastr

EXPOSE 80

CMD ["gunicorn", "wsgi:app", "--bind=0.0.0.0:80", "--workers=4", "--reload"]
