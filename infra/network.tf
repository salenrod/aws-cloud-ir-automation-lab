resource "aws_vpc" "lab" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = false

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "isolated" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.50.10.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.project_name}-isolated-subnet"
    NetworkType = "isolated"
  }
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "${var.project_name}-isolated-rt"
  }
}

resource "aws_route_table_association" "isolated" {
  subnet_id      = aws_subnet.isolated.id
  route_table_id = aws_route_table.isolated.id
}

resource "aws_security_group" "baseline" {
  name        = "${var.project_name}-baseline-sg"
  description = "Baseline security group for the disposable lab instance."
  vpc_id      = aws_vpc.lab.id

  revoke_rules_on_delete = true

  tags = {
    Name    = "${var.project_name}-baseline-sg"
    Purpose = "baseline"
  }
}

resource "aws_vpc_security_group_egress_rule" "baseline_all" {
  security_group_id = aws_security_group.baseline.id
  description       = "Baseline outbound rule; the isolated subnet has no route to the internet."

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"

  tags = {
    Name = "${var.project_name}-baseline-egress"
  }
}

resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine-sg"
  description = "No ingress or egress. Applied only during authorized containment."
  vpc_id      = aws_vpc.lab.id

  revoke_rules_on_delete = true

  tags = {
    Name    = "${var.project_name}-quarantine-sg"
    Purpose = "incident-containment"
  }
}