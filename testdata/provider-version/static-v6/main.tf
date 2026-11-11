resource "aws_lambda_function" "x" {
  function_name = "example"
  role          = "arn:aws:iam::111111111111:role/example"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "example.zip"
}
