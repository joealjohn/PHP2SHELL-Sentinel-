import os

from kombu import Queue

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

broker_url = REDIS_URL
result_backend = REDIS_URL
task_serializer = "json"
accept_content = ["json"]
result_serializer = "json"
timezone = "UTC"
enable_utc = True

task_track_started = True
task_acks_late = True
worker_prefetch_multiplier = 1
broker_connection_retry_on_startup = True

task_default_queue = "sentinel"
task_queues = (Queue("sentinel"),)

beat_schedule = {
    "schedule-due-scans": {
        "task": "app.workers.tasks.schedule_due_scans",
        "schedule": 60.0,
    },
    "sweep-stuck-scans": {
        "task": "app.workers.tasks.fail_stuck_scans",
        "schedule": 60.0,
    },
}
