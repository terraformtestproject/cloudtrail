resource "aws_cloudwatch_metric_alarm" "alarm_root_login_triggered" {
  alarm_name          = "${var.alarm_name}-metric"
  alarm_description   = var.alarm_description
  metric_name         = var.metric_name
  namespace           = var.namespace
  statistic           = var.statistic
  period              = var.period
  threshold           = var.threshold
  evaluation_periods  = var.evaluation_periods
  comparison_operator = var.comparison_operator
  datapoints_to_alarm = var.datapoints_to_alarm
  alarm_actions       = var.alarm_actions
  ok_actions          = var.ok_actions
  treat_missing_data  = var.treat_missing_data
}

resource "aws_cloudwatch_log_metric_filter" "root_login_metric_filter" {
  name           = "${var.alarm_name}-metric-filter"
  pattern        = var.pattern
  log_group_name = var.log_group_name

  metric_transformation {
    name      = var.metric_name
    namespace = var.namespace
    value     = var.value
  }
}
