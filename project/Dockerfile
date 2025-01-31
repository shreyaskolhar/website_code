FROM python:3.9-slim
WORKDIR /app
COPY requirment.txt .
RUN pip3 install --no-cache-dir -r requirment.txt
COPY . .
EXPOSE 5500
CMD python3 app.py

