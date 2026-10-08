resource "aws_api_gateway_rest_api" "plain" {
  name = "plain"
}

resource "aws_api_gateway_rest_api" "openapi" {
  name = "openapi"
  body = file("openapi.json")
}
