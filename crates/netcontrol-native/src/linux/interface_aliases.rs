use super::{Native, Parent, networking, read_json, remove_durable, session, write_json};
use crate::model::ethernet_kind;
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::Config;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    interface: Parent,
    boot: String,
    alias: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct State {
    scope: String,
    originals: BTreeMap<String, Snapshot>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    before: State,
    links: BTreeMap<String, Snapshot>,
}

fn label(display_name: &str, role: &str) -> String {
    let role = role.to_ascii_uppercase();
    if display_name.is_empty() {
        return role;
    }
    let suffix = format!(" [{role}]");
    // IFLA_IFALIAS has 255 payload bytes; keep the role and whole UTF-8 characters.
    let mut end = display_name.len().min(255 - suffix.len());
    while !display_name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", &display_name[..end])
}

fn alias(link: &LinkMessage) -> String {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfAlias(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn check(name: &str, snapshot: &Snapshot, live: &LinkMessage, boot: &str) -> Result<()> {
    let actual = networking::parent(live);
    ensure!(
        snapshot.interface.name == name
            && actual.name == name
            && ethernet_kind(&actual.kind)
            && actual.kind == snapshot.interface.kind
            && !actual.mac.is_empty()
            && actual.mac == snapshot.interface.mac
            && (snapshot.boot != boot || actual.index == snapshot.interface.index),
        "interface alias identity changed for {name}; refusing mutation"
    );
    Ok(())
}

async fn set(
    handle: &Handle,
    snapshots: &BTreeMap<String, Snapshot>,
    targets: &BTreeMap<String, String>,
    boot: &str,
) -> Result<()> {
    let live: BTreeMap<_, _> = networking::links(handle)
        .await?
        .into_iter()
        .map(|link| (networking::name(&link), link))
        .collect();
    for (name, snapshot) in snapshots {
        check(
            name,
            snapshot,
            live.get(name)
                .with_context(|| format!("interface alias link {name} missing"))?,
            boot,
        )?;
    }
    for (name, target) in targets {
        let link = live
            .get(name)
            .with_context(|| format!("interface alias link {name} missing"))?;
        if alias(link) != *target {
            let mut request = handle.link().set(link.header.index);
            request
                .message_mut()
                .attributes
                .push(LinkAttribute::IfAlias(target.clone()));
            request
                .execute()
                .await
                .with_context(|| format!("set interface alias for {name}"))?;
        }
    }
    let observed: BTreeMap<_, _> = networking::links(handle)
        .await?
        .into_iter()
        .map(|link| (networking::name(&link), link))
        .collect();
    for (name, target) in targets {
        let link = observed
            .get(name)
            .with_context(|| format!("interface alias readback link {name} missing"))?;
        check(name, &snapshots[name], link, boot)?;
        ensure!(
            alias(link) == *target,
            "interface alias readback mismatch for {name}"
        );
    }
    Ok(())
}

impl Native {
    pub(super) fn recover_interface_aliases(&self) -> Result<()> {
        let intent_path = self.state.join("interface-alias-intent.json");
        if !intent_path.try_exists()? {
            return Ok(());
        }
        self.check_scope()?;
        let intent: Intent = read_json(&intent_path)?;
        ensure!(
            intent.before.scope == self.identity,
            "interface alias recovery belongs to another namespace"
        );
        let targets = intent
            .links
            .iter()
            .map(|(name, snapshot)| (name.clone(), snapshot.alias.clone()))
            .collect();
        let boot = self.boot.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(set(handle, &intent.links, &targets, &boot))
        })
        .context("interface alias recovery failed; durable intent retained")?;
        write_json(&self.state.join("interface-aliases.json"), &intent.before)?;
        remove_durable(&intent_path)
    }

    pub(super) fn reconcile_interface_aliases(&self, config: &Config) -> Result<()> {
        self.check_scope()?;
        self.recover_interface_aliases()?;
        let state_path = self.state.join("interface-aliases.json");
        let before: State = if state_path.try_exists()? {
            read_json(&state_path)?
        } else {
            State {
                scope: self.identity.clone(),
                originals: BTreeMap::new(),
            }
        };
        ensure!(
            before.scope == self.identity,
            "interface alias ownership belongs to another namespace"
        );
        let wanted: BTreeMap<_, _> = config
            .interfaces
            .iter()
            .filter(|interface| interface.kind == "ethernet")
            .map(|interface| {
                (
                    interface.name.clone(),
                    label(&interface.metadata.display_name, &interface.role),
                )
            })
            .collect();
        let originals = before.originals.clone();
        let boot = self.boot.clone();
        let (snapshots, targets, next) = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(async {
                let live: BTreeMap<_, _> = networking::links(handle)
                    .await?
                    .into_iter()
                    .map(|link| (networking::name(&link), link))
                    .collect();
                let mut snapshots = BTreeMap::new();
                let mut targets = wanted.clone();
                let mut next = BTreeMap::new();
                for name in wanted.keys().chain(originals.keys()) {
                    if snapshots.contains_key(name) {
                        continue;
                    }
                    let link = live
                        .get(name)
                        .with_context(|| format!("interface alias link {name} missing"))?;
                    let current = Snapshot {
                        interface: networking::parent(link),
                        boot: boot.clone(),
                        alias: alias(link),
                    };
                    check(name, &current, link, &boot)?;
                    if let Some(original) = originals.get(name) {
                        check(name, original, link, &boot)?;
                    }
                    if wanted.contains_key(name) {
                        let mut original = current.clone();
                        if let Some(saved) = originals.get(name) {
                            original.alias.clone_from(&saved.alias);
                        }
                        next.insert(name.clone(), original);
                    } else {
                        targets.insert(name.clone(), originals[name].alias.clone());
                    }
                    snapshots.insert(name.clone(), current);
                }
                Ok((snapshots, targets, next))
            })
        })?;
        let next = State {
            scope: self.identity.clone(),
            originals: next,
        };
        if next == before
            && snapshots
                .iter()
                .all(|(name, snapshot)| snapshot.alias == targets[name])
        {
            return Ok(());
        }
        let intent_path = self.state.join("interface-alias-intent.json");
        write_json(
            &intent_path,
            &Intent {
                before,
                links: snapshots.clone(),
            },
        )?;
        let boot = self.boot.clone();
        let operation = (|| {
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(set(handle, &snapshots, &targets, &boot))
            })?;
            write_json(&state_path, &next)?;
            remove_durable(&intent_path)
        })();
        if let Err(error) = operation {
            return match self.recover_interface_aliases() {
                Ok(()) => {
                    Err(error.context("interface alias update failed; previous aliases restored"))
                }
                Err(rollback) => Err(anyhow!(
                    "interface alias update failed: {error:#}; rollback incomplete: {rollback:#}; durable intent retained"
                )),
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_keep_names_roles_and_utf8_within_kernel_limit() {
        assert_eq!(label("", "wan"), "WAN");
        assert_eq!(label("", "lan"), "LAN");
        assert_eq!(label("", "unassigned"), "UNASSIGNED");
        assert_eq!(label("Office uplink", "wan"), "Office uplink [WAN]");
        assert_eq!(label("WAN", "wan"), "WAN [WAN]");
        for role in ["wan", "lan", "unassigned"] {
            let name = "\u{1f310}".repeat(128);
            let value = label(&name, role);
            assert!(value.len() <= 255);
            assert!(value.ends_with(&format!(" [{}]", role.to_ascii_uppercase())));
            let prefix = value
                .strip_suffix(&format!(" [{}]", role.to_ascii_uppercase()))
                .unwrap();
            assert!(name.starts_with(prefix));
            assert_eq!(prefix.len() % 4, 0);
        }
    }
}
