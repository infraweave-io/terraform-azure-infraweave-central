locals {
  # Three- or four-character codes for Azure regions
  region_codes = tomap({

    # Asia–Pacific
    "australiacentral"   = "auc"
    "australiacentral2"  = "auc2"
    "australiaeast"      = "aue"
    "australiasoutheast" = "ause"
    "austriaeast"        = "ate"
    "eastasia"           = "eas"
    "indonesiacentral"   = "idc"
    "japaneast"          = "jpe"
    "japanwest"          = "jpw"
    "koreacentral"       = "krc"
    "koreasouth"         = "krs"
    "koreasouth2"        = "krs2"
    "newzealandnorth"    = "nzn"
    "southeastasia"      = "seas"
    "southindia"         = "sin"
    "centralindia"       = "cin"
    "westindia"          = "win"
    "jioindiacentral"    = "jic"
    "jioindiawest"       = "jiw"

    # Europe, Middle East & Africa
    "northeurope"        = "neu"
    "westeurope"         = "weu"
    "swedencentral"      = "swc"
    "norwayeast"         = "noe"
    "norwaywest"         = "now"
    "germanywestcentral" = "gwc"
    "germanynorth"       = "gen"
    "francecentral"      = "frc"
    "francesouth"        = "fras"
    "polandcentral"      = "plc"
    "spaincentral"       = "spc"
    "italynorth"         = "itn"
    "austriaeast"        = "ate"
    "switzerlandnorth"   = "chno"
    "switzerlandwest"    = "sww"
    "uknorth"            = "ukn"
    "uksouth"            = "uks"
    "ukwest"             = "ukw"
    "uaecentral"         = "uaec"
    "uaenorth"           = "uaen"
    "qatarcentral"       = "qac"
    "israelcentral"      = "isc"
    "southafricanorth"   = "san"
    "southafricawest"    = "saw"

    # Americas
    "eastus"         = "eus"
    "eastus2"        = "eus2"
    "centralus"      = "cus"
    "northcentralus" = "ncus"
    "southcentralus" = "scus"
    "westus"         = "wus"
    "westus2"        = "wus2"
    "westus3"        = "wus3"
    "westcentralus"  = "wcus"

    "canadacentral" = "cac"
    "canadaeast"    = "cae"

    "brazilsouth"     = "brs"
    "brazilsoutheast" = "brse"

    "mexicocentral" = "mxc"
    "chilecentral"  = "clc"

    # fallback pattern for any future region
    # "regionname" = substr(md5("regionname"), 0, 3)
  })
}
