.PHONY: help build up down restart logs shell migrate collectstatic createsuperuser test clean reset-migrations fix-permissions

help:
	@echo "Available commands:"
	@echo "  build          - Build Docker images"
	@echo "  up             - Start services"
	@echo "  down           - Stop and remove containers"
	@echo "  restart        - Restart services"
	@echo "  logs           - View logs"
	@echo "  shell          - Access Django shell"
	@echo "  bash           - Access container bash"
	@echo "  migrate        - Run database migrations"
	@echo "  makemigrations - Create new migrations"
	@echo "  collectstatic  - Collect static files"
	@echo "  createsuperuser - Create Django superuser"
	@echo "  test           - Run tests"
	@echo "  clean          - Clean up containers and volumes"
	@echo "  reset-migrations - Reset all migrations (fixes permission duplicates)"
	@echo "  fix-permissions - Quick fix for permission errors"
	@echo "  show-migrations - Show migration status"

# Main commands
build:
	docker compose build

up:
	docker compose up -d
	@echo "Services started. Access the app at http://localhost:8000"

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

logs-web:
	docker compose logs -f web

logs-db:
	docker compose logs -f db

# Container access
shell:
	docker compose exec web python manage.py shell

bash:
	docker compose exec web bash

# Django management commands
migrate:
	docker compose exec web python manage.py migrate

makemigrations:
	docker compose exec web python manage.py makemigrations

collectstatic:
	docker compose exec web python manage.py collectstatic --noinput

createsuperuser:
	docker compose exec web python manage.py createsuperuser

# Migration troubleshooting commands
show-migrations:
	@echo "Showing migration status..."
	docker compose exec web python manage.py showmigrations

fix-permissions:
	@echo "Fixing permission errors (quick fix)..."
	docker compose exec web python manage.py remove_stale_contenttypes --noinput
	docker compose exec web python manage.py migrate


# Testing
test:
	docker compose exec web python manage.py test

# Database commands
dbshell:
	docker-compose exec web python manage.py dbshell

# Cleanup
clean:
	docker compose down --volumes --remove-orphans
	docker system prune -f

# Backup
backup-db:
	@echo "Creating database backup..."
	docker compose exec web python manage.py dumpdata --natural-foreign --natural-primary > backup_$$(date +%Y%m%d_%H%M%S).json
	@echo "Backup created: backup_$$(date +%Y%m%d_%H%M%S).json"