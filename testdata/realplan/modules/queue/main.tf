variable "name" {
  type = string
}

resource "aws_sqs_queue" "q" {
  name = var.name
}
