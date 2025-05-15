locals {
  cosmosdb_container_names = {
    events         = "events"
    modules        = "modules"
    policies       = "policies"
    change_records = "change-records"
    deployments    = "deployments"
    configs        = "config"
  }

  storage_container_names = {
    modules        = "modules"
    policies       = "policies"
    change_records = "change-records"
    tf_state       = "tf-states"
    providers      = "providers"
  }
  subscription_id = data.azurerm_client_config.current.subscription_id
  proj_short      = substr(local.subscription_id, 0, 18)
  proj_supershort = substr(replace(local.subscription_id, "-", ""), 0, 11) # 0.0284% probability of collision in 100,000 subscriptions (birthday-paradox approximation)
  func_name       = "iw-${local.proj_short}-${var.region}-${var.environment}"
  db_name         = azurerm_cosmosdb_sql_database.db.name
  account_id      = azurerm_cosmosdb_account.cosmosdb.id

  workload_lookup = {
    for w in var.all_workload_projects :
    w.project_id => {
      function_name        = "iw-${substr(w.project_id, 0, 18)}-${var.region}-${var.environment}"
      runner_identity_name = "runner-id-${substr(w.project_id, 0, 18)}-${var.region}-${var.environment}"
    }
  }

  # reverse maps: name → project_id
  function_to_project = {
    for project_id, lookup in local.workload_lookup :
    lookup.function_name => project_id
  }
  runner_to_project = {
    for project_id, lookup in local.workload_lookup :
    lookup.runner_identity_name => project_id
  }

  # map name → object_id
  sp_name_to_oid = {
    for sp in data.azuread_service_principals.workload_mi.service_principals :
    sp.display_name => sp.object_id
  }
  runner_name_to_oid = {
    for sp in data.azuread_service_principals.runner_ui.service_principals :
    sp.display_name => sp.object_id
  }

  # build a map object_id → subscription_id
  oid_to_subscription = {
    for fname, project_id in local.function_to_project :
    local.sp_name_to_oid[fname] => project_id
    if can(local.sp_name_to_oid[fname])
  }
  runner_oid_to_subscription = {
    for rname, project_id in local.runner_to_project :
    local.runner_name_to_oid[rname] => project_id
    if can(local.runner_name_to_oid[rname])
  }

  region_short = lookup(
    local.region_codes,
    var.region,                   # full code like "westeurope" -> "weu"
    substr(md5(var.region), 0, 3) # fallback to a hash
  )
}

resource "azurerm_resource_group" "rg" {
  name     = "infraweave-central-${local.proj_short}-${var.region}-${var.environment}"
  location = var.region
}

resource "azurerm_cosmosdb_account" "cosmosdb" {
  name                = "iw-${local.proj_short}-${var.region}-${var.environment}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  capabilities {
    name = "EnableServerless"
  }

  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
}

resource "azurerm_cosmosdb_sql_database" "db" {
  name                = "db-infraweave"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
}

resource "azurerm_cosmosdb_sql_container" "events" {
  name                = local.cosmosdb_container_names.events
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  # TODO: partition further, as events can grow large
  partition_key_paths = ["/project_id"] # Subscription specific
}

resource "azurerm_cosmosdb_sql_container" "modules" {
  name                = local.cosmosdb_container_names.modules
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/PK"]
}

resource "azurerm_cosmosdb_sql_container" "policies" {
  name                = local.cosmosdb_container_names.policies
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/PK"]
}

resource "azurerm_cosmosdb_sql_container" "change_records" {
  name                = local.cosmosdb_container_names.change_records
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/project_id"] # Subscription specific
}

resource "azurerm_cosmosdb_sql_container" "deployments" {
  name                = local.cosmosdb_container_names.deployments
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/project_id"] # Subscription specific
}

resource "azurerm_cosmosdb_sql_container" "configs" {
  name                = local.cosmosdb_container_names.configs
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  database_name       = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths = ["/PK"]
}

# Since there is no data-plane resource in azure provider to create rows, we use azapi to create a UDF
resource "azapi_resource" "get_all_regions_udf" {
  type      = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions@2022-05-15"
  parent_id = azurerm_cosmosdb_sql_container.configs.id
  name      = "getAllRegions"

  body = {
    properties = {
      resource = {
        id   = "getAllRegions"
        body = "function getAllRegions() { return { regions: ${jsonencode(var.all_regions)} }; }"
      }
    }
  }

  # Disable the built-in schema check since azapi doesn’t know about this child type
  schema_validation_enabled = false
}

locals {
  transformed_project_map = {
    PK = "project_map"
    SK = "all"
    data = merge([
      for project in var.all_workload_projects : {
        for repo in project.github_repos_deploy : repo => {
          project_id = tostring(project.project_id)
        }
      }
    ]...)
  }
}

resource "azapi_resource" "get_project_map_udf" {
  type      = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions@2022-05-15"
  parent_id = azurerm_cosmosdb_sql_container.configs.id
  name      = "getProjectMap"

  body = {
    properties = {
      resource = {
        id   = "getProjectMap"
        body = "function getProjectMap() { return { ${jsonencode(local.transformed_project_map.data)} }"
      }
    }
  }

  # Disable the built-in schema check since azapi doesn’t know about this child type
  schema_validation_enabled = false
}

locals {
  project_items = [
    for project in var.all_workload_projects : {
      PK          = "PROJECTS"
      SK          = "PROJECT#${project.project_id}"
      project_id  = project.project_id
      name        = project.name
      description = project.description
      regions     = project.regions
      repositories = concat(
        [
          for repo in project.github_repos_deploy : {
            git_provider    = "github"
            git_url         = "https://github.com"
            repository_path = repo
            type            = "webhook"
          }
        ],
        [
          for repo in project.github_repos_oidc : {
            git_provider    = "github"
            git_url         = "https://github.com"
            repository_path = repo
            type            = "oidc"
          }
        ]
      )
    }
  ]
}

resource "azapi_resource" "get_all_projects_udf" {
  type      = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions@2022-05-15"
  parent_id = azurerm_cosmosdb_sql_container.configs.id
  name      = "getAllProjects"

  body = {
    properties = {
      resource = {
        id   = "getAllProjects"
        body = <<JS
function getAllProjects() {
  return ${jsonencode(local.project_items)};
}
JS
      }
    }
  }

  # Disable the built-in schema check since azapi doesn’t know about this child type
  schema_validation_enabled = false
}

resource "azurerm_storage_account" "storage" {
  name                     = "c${local.proj_supershort}${local.region_short}${var.environment}" # 24 chars limit (1 + 11 for subscription, 4 for region => 8 for env)
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_storage_account" "public_storage" {
  name                     = "p${local.proj_supershort}${local.region_short}${var.environment}" # 24 chars limit (1 + 11 for subscription, 4 for region => 8 for env)
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_storage_container" "modules" {
  name                  = local.storage_container_names.modules
  storage_account_id    = azurerm_storage_account.public_storage.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "policies" {
  name                  = local.storage_container_names.policies
  storage_account_id    = azurerm_storage_account.public_storage.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "providers" {
  name                  = local.storage_container_names.providers
  storage_account_id    = azurerm_storage_account.public_storage.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "function_blob_delegator_public" {
  for_each = local.oid_to_subscription

  role_definition_name = "Storage Blob Delegator"
  scope                = azurerm_storage_account.public_storage.id
  principal_id         = each.key
}

# Workload specific storage containers (separate for each workload)
resource "azurerm_storage_container" "workload_change_records" {
  for_each = local.workload_lookup

  name                  = "workload-change-records-${each.key}"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "runner_blob_owner_change_records" {
  for_each = local.runner_oid_to_subscription

  scope                = azurerm_storage_container.workload_change_records[each.value].id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = each.key
}

resource "azurerm_role_assignment" "function_blob_owner_change_records" {
  for_each = local.oid_to_subscription

  scope                = azurerm_storage_container.workload_change_records[each.value].id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = each.key
}

resource "azurerm_storage_container" "workload_tf_state" {
  for_each = local.workload_lookup

  name                  = "workload-tf-state-${each.key}"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "runner_blob_owner_tf_state" {
  for_each = local.runner_oid_to_subscription

  scope                = azurerm_storage_container.workload_tf_state[each.value].id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = each.key
}

resource "azurerm_role_assignment" "function_blob_owner_tf_state" {
  for_each = local.oid_to_subscription

  scope                = azurerm_storage_container.workload_tf_state[each.value].id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = each.key
}

resource "azurerm_service_plan" "function_plan" {
  name                = "sp-infraweave-${local.proj_short}-${var.region}-${var.environment}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "Y1"

}

data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = "${path.module}/api"
  output_path = "${path.module}/function2.zip"
}

resource "azurerm_storage_container" "function_deploy" {
  name                  = "function-deploy"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "function_blob" {
  name                   = "function2.zip"
  storage_account_name   = azurerm_storage_account.storage.name
  storage_container_name = azurerm_storage_container.function_deploy.name
  type                   = "Block"
  source                 = data.archive_file.function_zip.output_path

  depends_on = [data.archive_file.function_zip]
}

data "azurerm_storage_account_sas" "function_sas" {
  connection_string = azurerm_storage_account.storage.primary_connection_string
  https_only        = true

  start  = formatdate("2025-01-02", timestamp())
  expiry = formatdate("2026-01-02", timeadd(timestamp(), "8760h"))

  permissions {
    read    = true
    write   = false
    delete  = false
    list    = true
    add     = false
    create  = false
    update  = false
    process = false
    tag     = false
    filter  = false
  }

  resource_types {
    service   = false
    container = false
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }
}

resource "azurerm_linux_function_app" "function_app" {
  name                       = local.func_name
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  service_plan_id            = azurerm_service_plan.function_plan.id
  storage_account_name       = azurerm_storage_account.storage.name
  storage_account_access_key = azurerm_storage_account.storage.primary_access_key

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"       = "python"
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "FUNCTIONS_EXTENSION_VERSION"    = "~4"
    "AzureWebJobsFeatureFlags"       = "EnableWorkerIndexing"
    "WEBSITE_CONTENTSHARE"           = "functionappshare"
    "ENABLE_ORYX_BUILD"              = "true"

    "AZURE_SUBSCRIPTION_ID" = local.subscription_id
    "RESOURCE_GROUP_NAME"   = azurerm_resource_group.rg.name
    "LOCATION"              = azurerm_resource_group.rg.location
    "REGION"                = var.region

    "COSMOS_DB_ENDPOINT" = azurerm_cosmosdb_account.cosmosdb.endpoint
    "COSMOS_DB_DATABASE" = azurerm_cosmosdb_sql_database.db.name

    "PUBLIC_STORAGE_ACCOUNT_NAME" = azurerm_storage_account.public_storage.name
    "ACI_SUBNET_ID"               = azurerm_subnet.aci_subnet.id

    "EVENTS_TABLE_NAME"         = azurerm_cosmosdb_sql_container.events.name
    "MODULES_TABLE_NAME"        = azurerm_cosmosdb_sql_container.modules.name
    "POLICIES_TABLE_NAME"       = azurerm_cosmosdb_sql_container.policies.name
    "CHANGE_RECORDS_TABLE_NAME" = azurerm_cosmosdb_sql_container.change_records.name
    "DEPLOYMENTS_TABLE_NAME"    = azurerm_cosmosdb_sql_container.deployments.name
    "CONFIG_TABLE_NAME"         = azurerm_cosmosdb_sql_container.configs.name

    "MODULE_S3_BUCKET"    = azurerm_storage_container.modules.name
    "POLICY_S3_BUCKET"    = azurerm_storage_container.policies.name
    "PROVIDERS_S3_BUCKET" = azurerm_storage_container.providers.name

    "USER_ASSIGNED_IDENTITY_RESOURCE_ID" = azurerm_user_assigned_identity.aci_identity.id

    "LOG_ANALYTICS_WORKSPACE_ID"  = azurerm_log_analytics_workspace.container_logs.workspace_id
    "LOG_ANALYTICS_WORKSPACE_KEY" = azurerm_log_analytics_workspace.container_logs.primary_shared_key

    "OID_TO_SUBS_MAP_JSON" = jsonencode({
      for w, sp in data.azuread_service_principals.workload_mi.service_principals :
      sp.object_id => local.function_to_project[sp.display_name]
    })

    COSMOS_DB_KEY = azurerm_cosmosdb_account.cosmosdb.primary_key

    "BROKER_SECRET" = azuread_service_principal_password.broker_sp_secret.value
  }

  zip_deploy_file = data.archive_file.function_zip.output_path

  site_config {
    application_stack {
      python_version = "3.9"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  auth_settings_v2 {
    auth_enabled           = true
    require_https          = true
    require_authentication = true

    active_directory_v2 {
      client_id            = azuread_application.broker.client_id
      tenant_auth_endpoint = "https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/v2.0/"

      allowed_audiences = concat(
        [azuread_application.broker.client_id],
        [for uri in azuread_application.broker.identifier_uris : uri]
      )
    }

    login {}
  }
  depends_on = [azurerm_storage_blob.function_blob]
}

data "azurerm_client_config" "current" {}

locals {
  function_identity_object_id = azurerm_linux_function_app.function_app.identity[0].principal_id
  assignable_scope            = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${azurerm_resource_group.rg.name}/providers/Microsoft.DocumentDB/databaseAccounts/${azurerm_cosmosdb_account.cosmosdb.name}"
}

resource "azurerm_cosmosdb_sql_role_definition" "function_role" {
  name                = "FunctionAccessRole"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  type                = "CustomRole"
  assignable_scopes   = [local.assignable_scope]

  permissions {
    data_actions = [
      "Microsoft.DocumentDB/databaseAccounts/readMetadata",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/replace",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/upsert",
    ]
  }
}

resource "azurerm_cosmosdb_sql_role_assignment" "function_role_assignment" {
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name
  role_definition_id  = azurerm_cosmosdb_sql_role_definition.function_role.id
  principal_id        = local.function_identity_object_id
  scope               = local.assignable_scope
}

resource "azurerm_role_assignment" "function_managed_identity_operator" {
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Managed Identity Operator"
  scope                = azurerm_user_assigned_identity.aci_identity.id
}

resource "azurerm_role_assignment" "function_blob_data_contributor" {
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.public_storage.id
}

resource "azurerm_role_assignment" "function_blob_delegator" { # for delegating presigned url
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Storage Blob Delegator"
  scope                = azurerm_storage_account.public_storage.id
}

resource "azurerm_role_assignment" "aci_contributor" {
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Azure Container Instances Contributor Role"
  scope                = azurerm_resource_group.rg.id
}

resource "azurerm_role_assignment" "aci_subnet_join" {
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Network Contributor"
  scope                = azurerm_subnet.aci_subnet.id
}

resource "azurerm_role_assignment" "function_log_analytics_reader" {
  principal_id         = azurerm_linux_function_app.function_app.identity[0].principal_id
  role_definition_name = "Log Analytics Reader"
  scope                = azurerm_log_analytics_workspace.container_logs.id
}

resource "azurerm_virtual_network" "aci_vnet" {
  name                = "vnet-infraweave-${local.proj_short}-${var.region}-${var.environment}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "aci_subnet" {
  name                 = "aci-subnet-infraweave-${var.region}-${var.environment}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.aci_vnet.name
  address_prefixes     = ["10.1.1.0/24"]


  delegation {
    name = "aciDelegation"
    service_delegation {
      name = "Microsoft.ContainerInstance/containerGroups"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action",
      ]
    }
  }
}

resource "azurerm_user_assigned_identity" "aci_identity" {
  name                = "runner-id-${local.proj_short}-${var.region}-${var.environment}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
}

resource "azurerm_role_assignment" "aci_storage_role_function" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Account Key Operator Service Role"
  principal_id         = azurerm_user_assigned_identity.aci_identity.principal_id
}

resource "azurerm_log_analytics_workspace" "container_logs" {
  name                = "law-infraweave-${local.proj_short}-${var.region}-${var.environment}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 365
}

data "azuread_service_principals" "workload_mi" {
  # for_each     = local.workload_lookup
  # display_name = each.value.function_name
  display_names  = [for _, l in local.workload_lookup : l.function_name]
  ignore_missing = true
}

data "azuread_service_principals" "runner_ui" {
  # for_each     = local.workload_lookup
  # display_name = each.value.runner_identity_name
  display_names  = [for _, l in local.workload_lookup : l.runner_identity_name]
  ignore_missing = true
}

output "functions_with_access" {
  value = data.azuread_service_principals.workload_mi.service_principals
}

resource "azurerm_cosmosdb_sql_role_assignment" "module_reader_each" {
  for_each = local.oid_to_subscription

  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name

  # Cosmos DB Built-in Data Reader
  role_definition_id = "${azurerm_cosmosdb_account.cosmosdb.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"

  principal_id = each.key # the MI object-ID
  scope        = "${local.account_id}/dbs/${local.db_name}/colls/modules"
}

resource "azurerm_cosmosdb_sql_role_assignment" "policy_reader_each" {
  for_each = local.oid_to_subscription

  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name

  # Cosmos DB Built-in Data Reader
  role_definition_id = "${azurerm_cosmosdb_account.cosmosdb.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"

  principal_id = each.key # the MI object-ID
  scope        = "${local.account_id}/dbs/${local.db_name}/colls/policies"
}

resource "azurerm_cosmosdb_sql_role_assignment" "config_reader_each" {
  for_each = local.oid_to_subscription

  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmosdb.name

  # Cosmos DB Built-in Data Reader
  role_definition_id = "${azurerm_cosmosdb_account.cosmosdb.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"

  principal_id = each.key # the MI object-ID
  scope        = "${local.account_id}/dbs/${local.db_name}/colls/config"
}

resource "azurerm_role_assignment" "blob_modules" {
  for_each             = local.oid_to_subscription
  scope                = azurerm_storage_container.modules.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = each.key
}

resource "azurerm_role_assignment" "blob_providers" {
  for_each             = local.oid_to_subscription
  scope                = azurerm_storage_container.providers.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = each.key
}

resource "azuread_application" "broker" {
  display_name     = "api://infraweave-broker-${local.subscription_id}-${var.environment}-${var.region}"
  sign_in_audience = "AzureADMultipleOrgs"

  identifier_uris = [
    "api://infraweave-broker-${local.subscription_id}-${var.environment}-${var.region}",
  ]

  api {
    oauth2_permission_scope {
      id                         = uuid()
      admin_consent_description  = "Allow workloads to get per-subscription Cosmos tokens"
      admin_consent_display_name = "GetInfraWeaveToken"
      user_consent_description   = "Allow this app to generate resource tokens"
      user_consent_display_name  = "GenerateInfraWeaveToken"
      value                      = "access_as_infraweave"
      type                       = "User"
    }
  }
  app_role {
    id                   = uuid()
    display_name         = "InfraWeave Invoker"
    description          = "Allows principals to invoke the Function API"
    value                = "invoke_infraweave_app"
    allowed_member_types = ["User", "Application"]
  }

}

output "function_app_default_hostname" {
  description = "The default URL for the Function App"
  value       = azurerm_linux_function_app.function_app.default_hostname
}

resource "azuread_service_principal" "broker_sp" {
  client_id = azuread_application.broker.client_id
}

resource "azuread_service_principal_password" "broker_sp_secret" {
  service_principal_id = azuread_service_principal.broker_sp.id
  end_date             = timeadd(timestamp(), "8760h") # 1 year
}

resource "azuread_group" "function_invokers" {
  display_name     = "InfraWeave Function Invokers"
  security_enabled = true
}

resource "azuread_app_role_assignment" "group_app_role" {
  principal_object_id = azuread_group.function_invokers.object_id
  resource_object_id  = azuread_service_principal.broker_sp.object_id
  app_role_id         = one(azuread_application.broker.app_role).id
}

data "azuread_service_principal" "broker_sp" {
  client_id = azuread_application.broker.client_id
}

data "azuread_service_principal" "azure_cli" {
  client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Azure CLI App ID, see https://github.com/Azure/azure-cli/issues/28628#issuecomment-2302694201
}

resource "azuread_service_principal_delegated_permission_grant" "cli_broker_consent" {
  service_principal_object_id          = data.azuread_service_principal.azure_cli.object_id
  resource_service_principal_object_id = data.azuread_service_principal.broker_sp.object_id

  claim_values = [
    "access_as_infraweave"
  ]
}
