FROM python:3.8.6

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .
# WORKDIR /app

ENV FLASK_ENV=development \
    FLASK_DEBUG=True \ 
    FLASK_APP=app


# CMD python app_back.py --port=5001
CMD (FLASK_APP=app && flask run --port=5000 &) && (FLASK_APP=app_back && flask run -p 5001 &) && flask run --host=0.0.0.0 --port=$PORT

    
