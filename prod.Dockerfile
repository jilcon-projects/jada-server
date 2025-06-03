FROM python:3.11-slim

ARG SECRET_KEY
ARG DJANGO_SETTINGS_MODULE

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=buildcalc.settings.production
ENV SECRET_KEY=${SECRET_KEY}
# ENV DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE}

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app/

# Create static and media directories with proper permissions
RUN mkdir -p /app/static /app/media /app/staticfiles

# Collect static files (THIS IS THE KEY FIX)
RUN python manage.py collectstatic --noinput --clear --settings=buildcalc.settings.production

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "buildcalc.wsgi:application"]