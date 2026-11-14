# Automation guide
Engine = EventBus + TriggerManager + ScheduleManager + RuleEngine + WorkflowEngine + ActionRegistry + ApprovalManager + RetryManager + ExecutionLogger + NotificationManager over SQLite.
Triggers: events (auth_success, auth_failure, high_risk_session, repeated_failed_attempts, challenge_failure, unauthorized_command, permission_violation, security_alert,
model_training_completed, model_evaluation_completed, dataset_validation_failure, automation_failure), interval schedules (daily/weekly), manual.
Workflows: repeated_failed_auth, high_risk_auth, daily_report, weekly_analysis, model_health, database_backup, unauthorized_command, failure_recovery (+ dataset_integrity, log_cleanup, security_health_check).
Definition = JSON {triggers, conditions, steps[{name, action, params, when, requires_approval}], retry}. Params support `$field` and `{steps.<name>.<key>}` templating (no eval).
Statuses: running, waiting_for_approval, completed, failed, cancelled; action status adds retry_scheduled. Idempotency key per execution prevents duplicates.
Retries only for actions registered as retryable AND idempotent; failed executions resume from the failed step (earlier steps never re-run).
New workflow: edit JSON in Workflow Management (only registered actions accepted) or add to `definitions.py`; new action: register in `actions.py`.
Scheduler is interval-based (not cron) and runs only while the app/scheduler thread is running.
