
variable "region" {
  type        = string
  description = "Azure region (e.g. eastus, westeurope)"
}

variable "environment" {
  type        = string
  description = "Environment name (e.g. dev, prod)"
}

variable "all_regions" {
  description = "List of all regions that forms the InfraWeave platform"
  type        = list(string)
}

variable "all_workload_projects" {
  description = "List of workload project names to project id + regions, github_repos should to be set when `enable_webhook_processor` is true"
  type = list(
    object({
      project_id          = string
      name                = string
      description         = string
      regions             = list(string)
      github_repos_deploy = list(string)
      github_repos_oidc   = list(string)
    })
  )
}
