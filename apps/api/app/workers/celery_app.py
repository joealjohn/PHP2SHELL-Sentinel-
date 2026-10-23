from celery import Celery

celery_app = Celery("sentinel", include=["app.workers.tasks"])
celery_app.config_from_object("app.workers.celeryconfig")
