use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::{Context, Module, ModuleConfig};

use crate::configs::azurerm::AzureRMConfig;
use crate::formatter::StringFormatter;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AzureRMContext {
    default_context_key: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    contexts: HashMap<String, PSAzureContext>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct PSAzureContext {
    account: PSAzureAccount,
    #[serde(deserialize_with = "parse_azurerm_subscription")]
    subscription: PSAzureSubscription,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct PSAzureAccount {
    #[serde(default)]
    id: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
struct PSAzureSubscription {
    name: String,
    id: String,
}

fn parse_azurerm_subscription<'de, D>(d: D) -> Result<PSAzureSubscription, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or_default())
}

pub fn module<'a>(context: &'a Context) -> Option<Module<'a>> {
    let mut module = context.new_module("azurerm");
    let config = AzureRMConfig::try_load(module.config);

    if config.disabled {
        return None;
    };

    let azurerm_context: Option<PSAzureContext> = get_azurerm_context_info(context);

    if azurerm_context.is_none() {
        log::info!("Could not find Context in AzureRmContext.json");
        return None;
    }
    let azurerm_context = azurerm_context.unwrap();
    let subscription = azurerm_context.subscription;
    let account = azurerm_context.account;

    let parsed = StringFormatter::new(config.format).and_then(|formatter| {
        formatter
            .map_meta(|variable, _| match variable {
                "symbol" => Some(config.symbol),
                _ => None,
            })
            .map_style(|variable| match variable {
                "style" => Some(Ok(config.style)),
                _ => None,
            })
            .map(|variable| match variable {
                "subscription" => Some(Ok(config
                    .subscription_aliases
                    .get(&subscription.name)
                    .copied()
                    .unwrap_or(&subscription.name))),
                "username" => Some(Ok(&account.id)),
                _ => None,
            })
            .parse(None, Some(context))
    });

    module.set_segments(match parsed {
        Ok(segments) => segments,
        Err(error) => {
            log::warn!("Error in module `azurerm`:\n{}", error);
            return None;
        }
    });

    Some(module)
}

fn get_azurerm_context_info(context: &Context) -> Option<PSAzureContext> {
    let mut config_path = get_config_file_location(context)?;
    config_path.push("AzureRmContext.json");

    let azurerm_contexts = load_azurerm_context(&config_path)?;
    let azurerm_context_key = azurerm_contexts.default_context_key;
    let azurerm_context = azurerm_contexts
        .contexts
        .get(&azurerm_context_key)?
        .to_owned();

    Some(azurerm_context)
}

fn load_azurerm_context(config_path: &PathBuf) -> Option<AzureRMContext> {
    let json_data = fs::read_to_string(config_path).ok()?;
    let sanitized_json_data = json_data.strip_prefix('\u{feff}').unwrap_or(&json_data);
    if let Ok(azurerm_contexts) = serde_json::from_str::<AzureRMContext>(sanitized_json_data) {
        Some(azurerm_contexts)
    } else {
        log::info!("Failed to parse AzureRM Context.");
        None
    }
}

fn get_config_file_location(context: &Context) -> Option<PathBuf> {
    context
        .get_env("AZURE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            let mut home = context.get_home()?;
            home.push(".azure");
            Some(home)
        })
}

#[cfg(test)]
mod tests {
    use crate::modules::azurerm::load_azurerm_context;
    use crate::test::ModuleRenderer;
    use ini::Ini;
    use nu_ansi_term::Color;
    use std::fs::File;
    use std::io::{self, Write};
    use std::path::PathBuf;

    use tempfile::TempDir;

    fn generate_test_config(dir: &TempDir, azurerm_context_contents: &str) -> io::Result<()> {
        save_string_to_file(
            dir,
            azurerm_context_contents.to_string(),
            String::from("AzureRmContext.json"),
        )?;
        
        Ok(())
    }

    fn save_string_to_file(
        dir: &TempDir,
        contents: String,
        file_name: String,
    ) -> Result<PathBuf, io::Error> {
        let bom_file_path = dir.path().join(file_name);
        let mut bom_file = File::create(&bom_file_path)?;
        bom_file.write_all(contents.as_bytes())?;
        bom_file.sync_all()?;
        Ok(bom_file_path)
    }

    #[test]
    fn account_id_empty() -> io::Result<()> {
        let dir = tempfile::tempdir()?;

        let azurerm_context_contents = r#"{
            "DefaultContextKey": "SubscriptionA (ed85905b-8c3f-4d11-bf32-2fa9c579cba8) - 52b2e9cc-600c-4f1c-86c6-3878df1b6b7d - ",
            "EnvironmentTable": {},
            "Contexts": {
              "SubscriptionA (ed85905b-8c3f-4d11-bf32-2fa9c579cba8) - 52b2e9cc-600c-4f1c-86c6-3878df1b6b7d - ": {
                "Account": {
                  "Id": "",
                  "Credential": null,
                  "Type": "User",
                  "TenantMap": {},
                  "ExtendedProperties": {
                    "Tenants": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "HomeAccountId": "300f616c-5fbf-441d-97c2-3ea4827e107f.52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Subscriptions": "ed85905b-8c3f-4d11-bf32-2fa9c579cba8"
                  }
                },
                "Tenant": {
                  "Id": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                  "Directory": null,
                  "IsHome": true,
                  "ExtendedProperties": {}
                },
                "Subscription": {
                  "Id": "ed85905b-8c3f-4d11-bf32-2fa9c579cba8",
                  "Name": "SubscriptionA",
                  "State": "Enabled",
                  "ExtendedProperties": {
                    "SubscriptionPolices": "",
                    "AuthorizationSource": "RoleBased",
                    "HomeTenant": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Environment": "AzureCloud",
                    "Tenants": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Account": ""
                  }
                },
                "VersionProfile": null,
                "TokenCache": {
                  "CacheData": null
                },
                "ExtendedProperties": {}
              }
            },
            "ExtendedProperties": {}
          }          
        "#;

        generate_test_config(&dir, azurerm_context_contents)?;
        let dir_path = &dir.path().to_string_lossy();
        let actual = ModuleRenderer::new("azurerm")
            .config(toml::toml! {
            [azurerm]
            format = "on [$symbol($subscription:$username)]($style)"
            disabled = false
            })
            .env("AZURE_CONFIG_DIR", dir_path.as_ref())
            .collect();
        let expected = Some(format!(
            "on {}",
            Color::Blue.bold().paint("󰠅 SubscriptionA:")
        ));
        assert_eq!(actual, expected);
        dir.close()
    }

    #[test]
    fn subscription_name_missing_from_profile() -> io::Result<()> {
        let dir = tempfile::tempdir()?;

        let azurerm_context_contents = r#"{
            "DefaultContextKey": "SubscriptionA (ed85905b-8c3f-4d11-bf32-2fa9c579cba8) - 52b2e9cc-600c-4f1c-86c6-3878df1b6b7d - user@domain.com",
            "EnvironmentTable": {},
            "Contexts": {
              "SubscriptionA (ed85905b-8c3f-4d11-bf32-2fa9c579cba8) - 52b2e9cc-600c-4f1c-86c6-3878df1b6b7d - user@domain.com": {
                "Account": {
                  "Id": "user@domain.com",
                  "Credential": null,
                  "Type": "User",
                  "TenantMap": {},
                  "ExtendedProperties": {
                    "Tenants": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "HomeAccountId": "300f616c-5fbf-441d-97c2-3ea4827e107f.52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Subscriptions": "ed85905b-8c3f-4d11-bf32-2fa9c579cba8"
                  }
                },
                "Tenant": {
                  "Id": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                  "Directory": null,
                  "IsHome": true,
                  "ExtendedProperties": {}
                },
                "Subscription": {
                  "Id": "ed85905b-8c3f-4d11-bf32-2fa9c579cba8",
                  "Name": "SubscriptionA",
                  "State": "Enabled",
                  "ExtendedProperties": {
                    "SubscriptionPolices": "",
                    "AuthorizationSource": "RoleBased",
                    "HomeTenant": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Environment": "AzureCloud",
                    "Tenants": "52b2e9cc-600c-4f1c-86c6-3878df1b6b7d",
                    "Account": "user@domain.com"
                  }
                },
                "Environment": {
                  "Name": "AzureCloud",
                  "Type": "Discovered",
                  "OnPremise": false,
                  "ActiveDirectoryServiceEndpointResourceId": "https://management.core.windows.net/",
                  "AdTenant": "Common",
                  "GalleryUrl": null,
                  "ManagementPortalUrl": "https://portal.azure.com",
                  "ServiceManagementUrl": "https://management.core.windows.net/",
                  "PublishSettingsFileUrl": "https://go.microsoft.com/fwlink/?LinkID=301775",
                  "ResourceManagerUrl": "https://management.azure.com/",
                  "SqlDatabaseDnsSuffix": ".database.windows.net",
                  "StorageEndpointSuffix": "core.windows.net",
                  "ActiveDirectoryAuthority": "https://login.microsoftonline.com",
                  "GraphUrl": "https://graph.windows.net/",
                  "GraphEndpointResourceId": "https://graph.windows.net/",
                  "TrafficManagerDnsSuffix": "trafficmanager.net",
                  "AzureKeyVaultDnsSuffix": "vault.azure.net",
                  "DataLakeEndpointResourceId": "https://datalake.azure.net/",
                  "AzureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
                  "AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net",
                  "AzureKeyVaultServiceEndpointResourceId": "https://vault.azure.net",
                  "ContainerRegistryEndpointSuffix": "azurecr.io",
                  "VersionProfiles": [],
                  "ExtendedProperties": {
                    "ManagedHsmServiceEndpointResourceId": "https://managedhsm.azure.net",
                    "ContainerRegistryEndpointResourceId": "https://management.azure.com",
                    "AzureAppConfigurationEndpointResourceId": "https://azconfig.io",
                    "AzurePurviewEndpointSuffix": "purview.azure.net",
                    "ManagedHsmServiceEndpointSuffix": "managedhsm.azure.net",
                    "MicrosoftGraphUrl": "https://graph.microsoft.com",
                    "AzureAttestationServiceEndpointSuffix": "attest.azure.net",
                    "AzureSynapseAnalyticsEndpointSuffix": "dev.azuresynapse.net",
                    "AzureAnalysisServicesEndpointSuffix": "asazure.windows.net",
                    "AzureSynapseAnalyticsEndpointResourceId": "https://dev.azuresynapse.net",
                    "OperationalInsightsEndpointResourceId": "https://api.loganalytics.io",
                    "AnalysisServicesEndpointResourceId": "https://region.asazure.windows.net",
                    "AzurePurviewEndpointResourceId": "https://purview.azure.net",
                    "AzureAppConfigurationEndpointSuffix": "azconfig.io",
                    "AzureAttestationServiceEndpointResourceId": "https://attest.azure.net",
                    "MicrosoftGraphEndpointResourceId": "https://graph.microsoft.com/",
                    "OperationalInsightsEndpoint": "https://api.loganalytics.io/v1"
                  },
                  "BatchEndpointResourceId": "https://batch.core.windows.net/"
                },
                "VersionProfile": null,
                "TokenCache": {
                  "CacheData": null
                },
                "ExtendedProperties": {}
              }
            },
            "ExtendedProperties": {}
          }          
        "#;

        generate_test_config(&dir, azurerm_context_contents)?;
        let dir_path = &dir.path().to_string_lossy();
        let actual = ModuleRenderer::new("azurerm")
            .config(toml::toml! {
            [azurerm]
            format = "on [$symbol($subscription:$username)]($style)"
            disabled = false
            })
            .env("AZURE_CONFIG_DIR", dir_path.as_ref())
            .collect();
        let expected = None;
        assert_eq!(actual, expected);
        dir.close()
    }

    #[test]
    fn files_missing() -> io::Result<()> {
        let dir = tempfile::tempdir()?;

        let dir_path = &dir.path().to_string_lossy();

        let actual = ModuleRenderer::new("azurerm")
            .env("AZURE_CONFIG_DIR", dir_path.as_ref())
            .collect();
        let expected = None;
        assert_eq!(actual, expected);
        dir.close()
    }

}