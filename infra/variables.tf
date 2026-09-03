variable "aws_region" {
  description = "AWS Region used by the laboratory."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "This time-boxed laboratory must run in us-east-1."
  }
}

variable "project_name" {
  description = "Prefix applied to resources created by this laboratory."
  type        = string
  default     = "cloud-ir-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers and hyphens."
  }
}

variable "owner" {
  description = "Logical owner tag. Do not use an email address."
  type        = string
  default     = "Mateus"
}

variable "alert_email" {
  description = "Email address that receives incident notifications."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("@", var.alert_email))
    error_message = "alert_email must contain a valid-looking email address."
  }
}

variable "instance_type" {
  description = "EC2 instance type used as the disposable laboratory target."
  type        = string
  default     = "t3.micro"

  validation {
    condition = contains(
      ["t3.nano", "t3.micro"],
      var.instance_type
    )
    error_message = "Use t3.nano or t3.micro to keep the laboratory inexpensive."
  }
}

variable "evidence_retention_days" {
  description = "Number of days before S3 evidence objects expire."
  type        = number
  default     = 7

  validation {
    condition = (
      var.evidence_retention_days >= 1 &&
      var.evidence_retention_days <= 30
    )
    error_message = "Evidence retention must be between 1 and 30 days."
  }
}
variable "triage_minimum_severity" {
  description = "Minimum GuardDuty severity required for automatic containment eligibility."
  type        = number
  default     = 7

  validation {
    condition = (
      var.triage_minimum_severity >= 0 &&
      var.triage_minimum_severity <= 10
    )
    error_message = "triage_minimum_severity must be between 0 and 10."
  }
}
variable "incident_retention_days" {
  description = "Number of days to retain incident ledger records through DynamoDB TTL."
  type        = number
  default     = 7

  validation {
    condition = (
      var.incident_retention_days >= 1 &&
      var.incident_retention_days <= 30 &&
      floor(var.incident_retention_days) == var.incident_retention_days
    )
    error_message = "incident_retention_days must be an integer between 1 and 30."
  }
}

variable "containment_processing_lease_seconds" {
  description = "Duration of the DynamoDB processing lease used for containment idempotency."
  type        = number
  default     = 60

  validation {
    condition = (
      var.containment_processing_lease_seconds >= 30 &&
      var.containment_processing_lease_seconds <= 300 &&
      floor(var.containment_processing_lease_seconds) == var.containment_processing_lease_seconds
    )
    error_message = "containment_processing_lease_seconds must be an integer between 30 and 300."
  }
}