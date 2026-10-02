FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV CAMPUSSHIELD_DATA=/app/data
EXPOSE 5000
# Demo data is loaded on first start; bind to all interfaces inside the container only.
CMD ["sh", "-c", "python run.py demo >/dev/null && python run.py serve --host 0.0.0.0 --port 5000"]
