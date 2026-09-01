resource "aws_instance" "lab_target" {
  ami           = data.aws_ssm_parameter.al2023_ami.value
  instance_type = var.instance_type

  subnet_id                   = aws_subnet.isolated.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.baseline.id]

  ebs_optimized                        = true
  monitoring                           = false
  source_dest_check                    = true
  instance_initiated_shutdown_behavior = "stop"
  disable_api_termination              = false
  disable_api_stop                     = false
  get_password_data                    = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  volume_tags = {
    Name      = "${var.project_name}-target-root"
    Purpose   = "disposable-lab-volume"
    Evidence  = "eligible-for-snapshot"
    DataClass = "synthetic"
  }

  tags = {
    Name               = "${var.project_name}-target"
    Purpose            = "disposable-incident-response-target"
    AutoContainment    = "true"
    IncidentStatus     = "clean"
    DataClassification = "synthetic"
    InternetExposure   = "none"
  }
  lifecycle {
    # Use the latest AL2023 AMI during initial creation, but avoid an
    # unintended replacement when the public SSM parameter advances.
    ignore_changes = [ami]
  }
}