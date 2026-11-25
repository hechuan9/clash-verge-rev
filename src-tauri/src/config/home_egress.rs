use crate::{
    cmd::{CmdResult, StringifyErr as _},
    config::Config,
    core::{CoreManager, handle::Handle},
    utils::{dirs, help},
};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use std::{collections::BTreeMap, io::ErrorKind, net::Ipv4Addr};

const HOME: &str = "ChuanVPN";
const FILE: &str = "vpn.json";

#[derive(Deserialize, Serialize)]
struct Settings {
    domains: Vec<String>,
    wireguard: String,
}

#[derive(Serialize, specta::Type)]
pub struct HomeEgressView {
    domains: Vec<String>,
    server: Option<String>,
}

async fn read() -> Result<Option<Settings>> {
    match tokio::fs::read(dirs::app_home_dir()?.join(FILE)).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn parse_wireguard(source: &str) -> Result<Mapping> {
    let mut interface = BTreeMap::new();
    let mut peer = BTreeMap::new();
    let mut section = "";
    for line in source.trim_start_matches('\u{feff}').lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line == "[Interface]" && section.is_empty() {
            section = line;
            continue;
        }
        if line == "[Peer]" && section == "[Interface]" {
            section = line;
            continue;
        }
        let (key, value) = line.split_once('=').context("Invalid WireGuard configuration")?;
        let (key, value) = (key.trim(), value.trim());
        let fields = match (section, key) {
            ("[Interface]", "PrivateKey" | "Address" | "DNS" | "MTU") => &mut interface,
            ("[Peer]", "PublicKey" | "PresharedKey" | "Endpoint" | "AllowedIPs" | "PersistentKeepalive") => &mut peer,
            _ => bail!("Unsupported WireGuard directive"),
        };
        ensure!(
            !value.is_empty() && fields.insert(key, value).is_none(),
            "Invalid or duplicate WireGuard directive"
        );
    }

    let key = |fields: &BTreeMap<&str, &str>, name: &str| -> Result<String> {
        let value = fields.get(name).with_context(|| format!("Missing WireGuard {name}"))?;
        ensure!(
            STANDARD.decode(value).is_ok_and(|bytes| bytes.len() == 32),
            "Invalid WireGuard {name}"
        );
        Ok((*value).to_owned())
    };
    let (ip, prefix) = interface
        .get("Address")
        .and_then(|address| address.split_once('/'))
        .context("WireGuard Address must include an IPv4 prefix")?;
    let ip = ip.parse::<Ipv4Addr>().context("Invalid WireGuard IPv4 address")?;
    ensure!(
        prefix.parse::<u8>().is_ok_and(|bits| bits <= 32),
        "Invalid WireGuard IPv4 prefix"
    );

    let endpoint = peer.get("Endpoint").context("Missing WireGuard Endpoint")?;
    let (server, port) = endpoint
        .rsplit_once(':')
        .context("WireGuard Endpoint requires a port")?;
    if server.parse::<Ipv4Addr>().is_err() {
        ensure!(!server.starts_with("*."), "Invalid WireGuard server");
        domain_rule(server, HOME).context("Invalid WireGuard server")?;
    }
    let port = port.parse::<u16>().context("Invalid WireGuard port")?;
    ensure!(port != 0, "Invalid WireGuard port");
    ensure!(
        peer.get("AllowedIPs").copied() == Some("0.0.0.0/0"),
        "WireGuard AllowedIPs must be 0.0.0.0/0"
    );

    let mut node = Mapping::new();
    node.insert("name".into(), HOME.into());
    node.insert("type".into(), "wireguard".into());
    node.insert("server".into(), server.into());
    node.insert("port".into(), port.into());
    node.insert("ip".into(), ip.to_string().into());
    node.insert("private-key".into(), key(&interface, "PrivateKey")?.into());
    node.insert("public-key".into(), key(&peer, "PublicKey")?.into());
    node.insert("allowed-ips".into(), serde_yaml_ng::to_value(["0.0.0.0/0"])?);
    node.insert("udp".into(), true.into());
    if peer.contains_key("PresharedKey") {
        node.insert("pre-shared-key".into(), key(&peer, "PresharedKey")?.into());
    }
    if let Some(value) = peer.get("PersistentKeepalive") {
        let keepalive = value.parse::<u16>().context("Invalid WireGuard PersistentKeepalive")?;
        node.insert("persistent-keepalive".into(), keepalive.into());
    }
    if let Some(value) = interface.get("MTU") {
        let mtu = value.parse::<u16>().context("Invalid WireGuard MTU")?;
        ensure!(mtu >= 576, "Invalid WireGuard MTU");
        node.insert("mtu".into(), mtu.into());
    }
    if let Some(value) = interface.get("DNS") {
        let dns = value
            .split(',')
            .map(|address| address.trim().parse::<Ipv4Addr>().map(|ip| ip.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .context("Invalid WireGuard DNS address")?;
        node.insert("remote-dns-resolve".into(), true.into());
        node.insert("dns".into(), serde_yaml_ng::to_value(dns)?);
    }
    Ok(node)
}

fn domain_rule(input: &str, target: &str) -> Result<String> {
    let (kind, host) = input
        .strip_prefix("*.")
        .map_or(("DOMAIN", input), |host| ("DOMAIN-SUFFIX", host));
    ensure!(
        host.len() <= 253
            && host.contains('.')
            && host.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "Invalid site domain"
    );
    Ok(format!("{kind},{host},{target}"))
}

pub async fn apply(config: &mut Mapping) -> Result<()> {
    let Some(settings) = read().await? else {
        return Ok(());
    };
    compose(config, &settings)
}

fn compose(config: &mut Mapping, settings: &Settings) -> Result<()> {
    let node = parse_wireguard(&settings.wireguard)?;
    let mut rules = settings
        .domains
        .iter()
        .map(|d| domain_rule(d, HOME).map(Value::from))
        .collect::<Result<Vec<_>>>()?;
    let existing = config
        .get_mut("rules")
        .and_then(Value::as_sequence_mut)
        .context("Missing subscription rules")?;
    rules.append(existing);
    *existing = rules;

    for key in ["proxies", "proxy-groups"] {
        ensure!(
            !config
                .get(key)
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .any(|p| p.get("name").and_then(Value::as_str) == Some(HOME)),
            "Conflicting ChuanVPN name in profile"
        );
    }
    if let Some(groups) = config.get_mut("proxy-groups").and_then(Value::as_sequence_mut) {
        for group in groups {
            if ["include-all", "include-all-proxies"]
                .iter()
                .any(|k| group.get(*k).and_then(Value::as_bool) == Some(true))
            {
                let filter = match group.get("exclude-filter").and_then(Value::as_str) {
                    Some(f) if !f.is_empty() => format!("{f}`^{HOME}$"),
                    _ => format!("^{HOME}$"),
                };
                group["exclude-filter"] = filter.into();
            }
        }
    }
    config
        .entry("proxies".into())
        .or_insert_with(|| Value::Sequence(vec![]))
        .as_sequence_mut()
        .context("Invalid subscription nodes")?
        .push(Value::Mapping(node));
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn get_home_egress() -> CmdResult<HomeEgressView> {
    let settings = read().await.stringify_err()?;
    let server = settings
        .as_ref()
        .map(|s| parse_wireguard(&s.wireguard))
        .transpose()
        .stringify_err()?
        .and_then(|n| Some(format!("{}:{}", n.get("server")?.as_str()?, n.get("port")?.as_u64()?)));
    Ok(HomeEgressView {
        server,
        domains: settings.map(|s| s.domains).unwrap_or_default(),
    })
}

#[tauri::command]
#[specta::specta]
pub async fn save_home_egress(domains: Vec<String>, wireguard: Option<String>) -> CmdResult<()> {
    save(domains, wireguard).await.stringify_err()
}

async fn save(domains: Vec<String>, wireguard: Option<String>) -> Result<()> {
    let write = Config::lock_config_write().await;
    let manager = CoreManager::global();
    let update = manager.claim_config_update(&write)?;
    let prior = read().await?;
    let wireguard = wireguard
        .or_else(|| prior.as_ref().map(|p| p.wireguard.clone()))
        .context("Import a WireGuard profile first")?;
    parse_wireguard(&wireguard)?;
    for domain in &domains {
        domain_rule(domain, HOME)?;
    }
    let next = Settings { domains, wireguard };
    let path = dirs::app_home_dir()?.join(FILE);
    help::save_yaml_str(&path, &serde_json::to_string(&next)?).await?;
    if let Err(error) = manager.update_config_in_patch(&update).await {
        if let Some(previous) = prior {
            help::save_yaml_str(&path, &serde_json::to_string(&previous)?).await?;
        } else {
            tokio::fs::remove_file(&path).await?;
        }
        manager
            .update_config_in_patch(&update)
            .await
            .map_err(|_| anyhow!("Apply failed; previous settings restored on disk but core reload failed"))?;
        bail!("{error}");
    }
    drop(update);
    drop(write);
    Handle::refresh_clash();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_rules_precede_subscription_rules() -> Result<()> {
        let mut config: Mapping = serde_yaml_ng::from_str("rules: ['MATCH,DIRECT']")?;
        let key = STANDARD.encode([1; 32]);
        let wireguard = format!(
            "[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = {key}\nDNS = 1.1.1.1\nMTU = 1380\n\n[Peer]\nPublicKey = {key}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0"
        );
        compose(
            &mut config,
            &Settings {
                domains: vec!["*.example.org".into()],
                wireguard,
            },
        )?;
        assert_eq!(
            config["rules"],
            serde_yaml_ng::to_value(["DOMAIN-SUFFIX,example.org,ChuanVPN", "MATCH,DIRECT"])?
        );
        let node = &config["proxies"][0];
        assert_eq!(node["type"].as_str(), Some("wireguard"));
        assert_eq!(node["server"].as_str(), Some("192.0.2.1"));
        assert_eq!(node["port"].as_u64(), Some(51820));
        assert_eq!(node["mtu"].as_u64(), Some(1380));
        Ok(())
    }
}
