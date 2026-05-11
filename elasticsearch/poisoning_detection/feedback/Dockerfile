FROM python:3.11-slim

WORKDIR /app

# Install deps required by feedback + retraining (includes numpy/pandas/sklearn)
COPY poisoning_detection/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# Copy just the poisoning_detection package (keeps image smaller + paths consistent)
COPY poisoning_detection /app/poisoning_detection

ENV PYTHONPATH=/app

CMD ["python", "-m", "poisoning_detection.feedback.feedback_daemon"]