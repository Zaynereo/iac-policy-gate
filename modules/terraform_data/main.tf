# Optional fmt/validate target without providers or network init.
terraform {
  required_version = ">= 1.5.0"
}

resource "terraform_data" "policy_gate_fixture_label" {
  input = "synthetic-not-aws"
}
