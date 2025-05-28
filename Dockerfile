FROM python:3.11-slim

# Accept SECRET_KEY as build argument
ARG SECRET_KEY
ENV SECRET_KEY=${SECRET_KEY}

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=buildcalc.settings.production

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

# Now collectstatic will work because SECRET_KEY is available
RUN python manage.py collectstatic --noinput --clear --settings=buildcalc.settings.production

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "buildcalc.wsgi:application"]