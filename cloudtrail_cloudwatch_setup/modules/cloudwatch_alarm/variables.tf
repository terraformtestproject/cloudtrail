variable "alarm_name" {
  type = string
}
variable "alarm_description" {
  type = string
}
variable "metric_name" {
  type = string
}
variable "namespace" {
  type = string
}
variable "statistic" {
  type = string
}
variable "period" {
  type = string
}
variable "threshold" {
  type = string
}
variable "evaluation_periods" {
  type = string
}
variable "comparison_operator" {
  type = string
}
variable "datapoints_to_alarm" {
  type = string
}
variable "alarm_actions" {
  type = list(any)
}
variable "ok_actions" {
  type = list(any)
}
variable "treat_missing_data" {
  type = string
}
variable "pattern" {
  type = string
}
variable "log_group_name" {
  type = string
}
variable "value" {
  type = string
}

