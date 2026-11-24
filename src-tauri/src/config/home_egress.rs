use crate::{
    cmd::{CmdResult, StringifyErr as _},
    config::Config,
    core::{CoreManager, handle::Handle},
    utils::{dirs, help},
};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use std::io::ErrorKind;

const HOME: &str = "ChuanVPN";
const FILE: &str = "home-egress.json";

#[derive(Deserialize, Serialize)]
struct Settings {
    carrier: String,
    domains: Vec<String>,
    ovpn: String,
}

#[derive(Serialize, specta::Type)]
pub struct HomeEgressView {
    carrier: Option<String>,
    candidates: Vec<String>,
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

fn parse_deco(source: &str) -> Result<Mapping> {
    let mut node = Mapping::new();
    let mut lines = source.trim_start_matches('\u{feff}').lines().map(str::trim);
    let mut udp = false;
    while let Some(line) = lines.next() {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            ensure!(
                matches!(tag, "ca" | "cert" | "key" | "tls-auth" | "tls-crypt"),
                "Unsupported OpenVPN block"
            );
            let end = format!("</{tag}>");
            let mut data = String::new();
            loop {
                let next = lines.next().context("Incomplete OpenVPN block")?;
                if next == end {
                    break;
                }
                data.push_str(next);
                data.push('\n');
            }
            ensure!(!data.trim().is_empty(), "Empty OpenVPN block");
            node.insert(tag.into(), data.into());
            continue;
        }
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["proto", "udp" | "udp4"] => udp = true,
            ["remote", server, port] => {
                ensure!(!node.contains_key("server"), "Only one Deco endpoint is supported");
                let port: u16 = port.parse().context("Invalid Deco UDP port")?;
                ensure!(port > 0, "Invalid Deco UDP port");
                node.insert("server".into(), (*server).into());
                node.insert("port".into(), port.into());
            }
            [
                key @ ("cipher" | "auth" | "data-ciphers-fallback" | "comp-lzo" | "key-direction"),
                value,
            ] => {
                node.insert((*key).into(), (*value).into());
            }
            ["data-ciphers", value] => {
                node.insert(
                    "data-ciphers".into(),
                    serde_yaml_ng::to_value(value.split(':').collect::<Vec<_>>())?,
                );
            }
            ["client" | "float" | "nobind" | "persist-key" | "persist-tun"]
            | ["dev", "tun"]
            | ["resolv-retry", "infinite"]
            | ["remote-cert-tls", "server"]
            | ["verb", _] => {}
            _ => bail!("Unsupported directive in Deco OpenVPN UDP profile"),
        }
    }
    ensure!(
        udp && ["server", "ca", "cert", "key"]
            .iter()
            .all(|key| node.contains_key(*key)),
        "A Deco UDP profile with embedded CA, certificate and key is required"
    );
    if let Some(cipher) = node.get("cipher").cloned() {
        node.entry("data-ciphers-fallback".into()).or_insert(cipher);
    }
    node.entry("auth".into()).or_insert_with(|| "SHA1".into());
    node.insert("name".into(), HOME.into());
    node.insert("type".into(), "openvpn".into());
    node.insert("proto".into(), "udp".into());
    node.insert("udp".into(), true.into());
    node.insert("remote-dns-resolve".into(), true.into());
    node.insert("dns".into(), serde_yaml_ng::to_value(["8.8.8.8"])?);
    Ok(node)
}

fn candidates(config: &Mapping) -> Vec<String> {
    config
        .get("proxy-groups")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter(|group| group.get("disable-udp").and_then(Value::as_bool) != Some(true))
        .filter_map(|group| group.get("name")?.as_str().map(str::to_owned))
        .collect()
}

fn legacy_carrier(config: &Mapping, name: &str) -> bool {
    config
        .get("proxies")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .any(|p| {
            p.get("name").and_then(Value::as_str) == Some(name)
                && p.get("udp").and_then(Value::as_bool) == Some(true)
                && p.get("dialer-proxy").is_none()
        })
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
    let available = candidates(config).contains(&settings.carrier) || legacy_carrier(config, &settings.carrier);
    let target = if available { HOME } else { "REJECT" };
    let mut rules = settings
        .domains
        .iter()
        .map(|d| domain_rule(d, target).map(Value::from))
        .collect::<Result<Vec<_>>>()?;
    let existing = config
        .get_mut("rules")
        .and_then(Value::as_sequence_mut)
        .context("Missing subscription rules")?;
    rules.append(existing);
    *existing = rules;
    if !available {
        return Ok(());
    }

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
    let mut node = parse_deco(&settings.ovpn)?;
    node.insert("dialer-proxy".into(), settings.carrier.clone().into());
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
    let runtime = Config::runtime().await;
    let candidates = runtime.data_arc().config.as_ref().map(candidates).unwrap_or_default();
    let server = settings
        .as_ref()
        .map(|s| parse_deco(&s.ovpn))
        .transpose()
        .stringify_err()?
        .and_then(|n| n.get("server")?.as_str().map(str::to_owned));
    Ok(HomeEgressView {
        carrier: settings.as_ref().map(|s| s.carrier.clone()),
        candidates,
        server,
        domains: settings.map(|s| s.domains).unwrap_or_default(),
    })
}

#[tauri::command]
#[specta::specta]
pub async fn save_home_egress(carrier: String, domains: Vec<String>, ovpn: Option<String>) -> CmdResult<()> {
    save(carrier, domains, ovpn).await.stringify_err()
}

async fn save(carrier: String, domains: Vec<String>, ovpn: Option<String>) -> Result<()> {
    let write = Config::lock_config_write().await;
    let manager = CoreManager::global();
    let update = manager.claim_config_update(&write)?;
    let prior = read().await?;
    let ovpn = ovpn
        .or_else(|| prior.as_ref().map(|p| p.ovpn.clone()))
        .context("Import a Deco profile first")?;
    parse_deco(&ovpn)?;
    for domain in &domains {
        domain_rule(domain, HOME)?;
    }
    let runtime = Config::runtime().await;
    let current = runtime.data_arc();
    let config = current.config.as_ref().context("No active subscription")?;
    ensure!(
        candidates(config).contains(&carrier)
            || prior
                .as_ref()
                .is_some_and(|old| old.carrier == carrier && legacy_carrier(config, &carrier)),
        "Select an available UDP carrier group"
    );
    let next = Settings { carrier, domains, ovpn };
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
    fn missing_group_blocks_only_home_domains() -> Result<()> {
        let mut config: Mapping = serde_yaml_ng::from_str(
            "proxy-groups: [{name: Other, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,Other']",
        )?;
        compose(
            &mut config,
            &Settings {
                carrier: "Removed".into(),
                domains: vec!["*.example.org".into()],
                ovpn: String::new(),
            },
        )?;
        assert_eq!(
            config["rules"],
            serde_yaml_ng::to_value(["DOMAIN-SUFFIX,example.org,REJECT", "MATCH,Other"])?
        );
        Ok(())
    }
}
