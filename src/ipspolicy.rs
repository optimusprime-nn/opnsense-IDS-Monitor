//! Manage one OPNsense Intrusion Detection policy that switches high-risk rulesets from
//! Alert to Drop. Always planned (read-only dry run) before anything is written.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::opnsense::OPNsense;

/// Description used to find "our" policy again (update / remove instead of duplicating).
pub const POLICY_DESCRIPTION: &str = "IPS Watch - drop high-risk";

/// High-risk rulesets by base name (the filename without `.rules` and without an
/// `et_open.` / `et_pro.` prefix). Only rulesets you have enabled are used.
pub const DEFAULT_RULESETS: &[&str] = &[
    "abuse.ch.feodotracker",
    "abuse.ch.sslblacklist",
    "abuse.ch.sslipblacklist",
    "abuse.ch.threatfox",
    "abuse.ch.urlhaus",
    "botcc",
    "botcc.portgrouped",
    "compromised",
    "drop",
    "dshield",
    "ciarmy",
    "3coresec",
    "emerging-exploit",
    "emerging-exploit_kit",
    "emerging-attack_response",
    "emerging-malware",
    "emerging-mobile_malware",
    "emerging-trojan",
    "emerging-worm",
    "emerging-phishing",
    "emerging-coinminer",
    "snort_vrt.malware-cnc",
    "snort_vrt.malware-backdoor",
    "snort_vrt.exploit-kit",
    "snort_vrt.indicator-compromise",
];

pub fn base_name(filename: &str) -> &str {
    let f = filename.strip_suffix(".rules").unwrap_or(filename);
    f.strip_prefix("et_open.").or_else(|| f.strip_prefix("et_pro.")).unwrap_or(f)
}

#[derive(Clone, Debug)]
pub struct RulesetPlan {
    pub filename: String,
    pub uuid: String,
    pub rules: u64,
    /// Rules currently on Alert - the ones the policy turns into Drop.
    pub alert_rules: u64,
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub mode: String,
    pub ips_on: bool,
    pub interfaces: String,
    pub existing: Option<String>, // uuid of our policy
    pub selected: Vec<RulesetPlan>,
    pub not_enabled: Vec<String>,
    /// Enabled but with no rules installed (left out of the policy).
    pub empty: Vec<String>,
    pub not_installed: Vec<String>,
    pub other_policies: usize,
}

impl Plan {
    pub fn total_changes(&self) -> u64 {
        self.selected.iter().map(|r| r.alert_rules).sum()
    }

    pub fn payload(&self) -> Value {
        let uuids: Vec<&str> = self.selected.iter().map(|r| r.uuid.as_str()).collect();
        json!({"policy": {
            "enabled": "1",
            "prio": "10",
            "action": "alert",           // only rules currently on Alert...
            "rulesets": uuids.join(","),
            "content": "",               // ...of any kind within these rulesets
            "new_action": "drop",        // ...become Drop
            "description": POLICY_DESCRIPTION,
        }})
    }

    /// Plain-text review of what applying would do.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s += &format!(
            "IPS mode: {}{}\nInspected interfaces: {}\n",
            self.mode,
            if self.ips_on { "" } else { "  <-- NOT an IPS mode: Drop rules won't block anything until you switch to Netmap (IPS)" },
            if self.interfaces.is_empty() { "(none)" } else { &self.interfaces }
        );
        s += &match &self.existing {
            Some(u) => format!("Existing \"{POLICY_DESCRIPTION}\" policy found ({u}): it would be UPDATED.\n"),
            None => format!("No \"{POLICY_DESCRIPTION}\" policy yet: one would be CREATED.\n"),
        };
        if self.other_policies > 0 {
            s += &format!("You have {} other polic(ies); they are left untouched.\n", self.other_policies);
        }
        s += &format!(
            "\nPolicy: rules on Alert in the {} rulesets below -> Drop (priority 10)\n\n",
            self.selected.len()
        );
        s += &format!("  {:<44} {:>8} {:>12}\n", "Ruleset", "Rules", "Alert->Drop");
        for r in &self.selected {
            s += &format!("  {:<44} {:>8} {:>12}\n", r.filename, r.rules, r.alert_rules);
        }
        s += &format!("  {:<44} {:>8} {:>12}\n", "TOTAL", self.selected.iter().map(|r| r.rules).sum::<u64>(), self.total_changes());
        if !self.not_enabled.is_empty() {
            s += &format!("\nInstalled but not enabled (skipped): {}\n", self.not_enabled.join(", "));
        }
        if !self.empty.is_empty() {
            s += &format!("
Enabled but contain no rules (left out): {}
", self.empty.join(", "));
        }
        if !self.not_installed.is_empty() {
            s += &format!("Not available on this firewall (skipped): {}\n", self.not_installed.join(", "));
        }
        s += "\nEverything else stays on Alert (app detection, INFO, P2P, SCAN, POLICY...).\n\
              Applying reloads Suricata: expect a few seconds of interruption on the inspected interfaces.\n\
              Undo at any time with \"Remove policy\" (or ipswatch-cli ips-policy --remove).";
        s
    }
}

fn selected_key(v: &Value) -> String {
    v.as_object()
        .and_then(|m| m.iter().find(|(_, o)| o.get("selected").and_then(Value::as_i64) == Some(1)))
        .map(|(k, o)| o.get("value").and_then(Value::as_str).unwrap_or(k).to_string())
        .unwrap_or_default()
}

fn selected_list(v: &Value) -> String {
    match v {
        Value::Object(m) => m
            .iter()
            .filter(|(_, o)| o.get("selected").and_then(Value::as_i64) == Some(1))
            .map(|(k, o)| o.get("value").and_then(Value::as_str).unwrap_or(k).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn count_rules(api: &OPNsense, filename: &str, action: Option<&str>) -> Result<u64> {
    let mut body = json!({"current": 1, "rowCount": 1, "searchPhrase": "", "source": filename});
    if let Some(a) = action {
        body["action"] = json!(a);
    }
    let v = api.post_raw("ids/settings/search_installed_rules", body)?;
    Ok(v.get("total").and_then(Value::as_u64).unwrap_or(0))
}

fn find_policy(api: &OPNsense) -> Result<(Option<String>, usize)> {
    let v = api.post_raw("ids/settings/search_policy", json!({"current": 1, "rowCount": -1, "searchPhrase": ""}))?;
    let rows = v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
    let ours = rows
        .iter()
        .find(|r| r.get("description").and_then(Value::as_str) == Some(POLICY_DESCRIPTION))
        .and_then(|r| r.get("uuid").and_then(Value::as_str))
        .map(String::from);
    let others = rows.len() - usize::from(ours.is_some());
    Ok((ours, others))
}

/// Read-only: work out exactly what applying would change.
pub fn plan(api: &OPNsense, wanted: &[String]) -> Result<Plan> {
    let general = api.get_raw("ids/settings/get")?;
    let g = general.pointer("/ids/general").context("unexpected ids/settings/get response")?;
    let mode = g.get("mode").map(selected_key).unwrap_or_else(|| {
        if g.get("ips").and_then(Value::as_str) == Some("1") { "IPS".into() } else { "IDS".into() }
    });
    let ips_on = !mode.to_lowercase().contains("pcap") && !mode.to_uppercase().contains("(IDS)") && mode != "IDS";
    let interfaces = g.get("interfaces").map(selected_list).unwrap_or_default();

    // uuid <-> filename from the policy template; enabled flag from the ruleset list.
    let template = api.get_raw("ids/settings/get_policy")?;
    let mut uuid_by_file: HashMap<String, String> = HashMap::new();
    if let Some(m) = template.pointer("/policy/rulesets").and_then(Value::as_object) {
        for (uuid, o) in m {
            if let Some(f) = o.get("value").and_then(Value::as_str) {
                uuid_by_file.insert(f.to_string(), uuid.clone());
            }
        }
    }
    let list = api.get_raw("ids/settings/list_rulesets")?;
    let enabled: HashMap<String, bool> = list
        .get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|r| Some((r.get("filename")?.as_str()?.to_string(), r.get("enabled").and_then(Value::as_str) == Some("1"))))
                .collect()
        })
        .unwrap_or_default();

    let mut files: Vec<&String> = uuid_by_file.keys().collect();
    files.sort();
    let (mut selected, mut not_enabled, mut empty) = (Vec::new(), Vec::new(), Vec::new());
    let mut matched_patterns = std::collections::HashSet::new();
    for f in files {
        let base = base_name(f);
        let Some(pat) = wanted.iter().find(|w| w.trim() == base) else { continue };
        matched_patterns.insert(pat.trim().to_string());
        if !enabled.get(f.as_str()).copied().unwrap_or(false) {
            not_enabled.push(f.clone());
            continue;
        }
        let rules = count_rules(api, f, None)?;
        if rules == 0 {
            empty.push(f.clone());
            continue;
        }
        selected.push(RulesetPlan {
            filename: f.clone(),
            uuid: uuid_by_file[f].clone(),
            rules,
            alert_rules: count_rules(api, f, Some("alert"))?,
        });
    }
    let not_installed = wanted.iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty() && !matched_patterns.contains(w)).collect();
    let (existing, other_policies) = find_policy(api)?;
    Ok(Plan { mode, ips_on, interfaces, existing, selected, not_enabled, empty, not_installed, other_policies })
}

fn check_saved(v: &Value, what: &str) -> Result<()> {
    match v.get("result").and_then(Value::as_str) {
        Some("saved") | Some("deleted") | Some("ok") => Ok(()),
        _ => bail!("{what} was not accepted by the firewall: {v}"),
    }
}

fn reconfigure(api: &OPNsense) -> Result<()> {
    let v = api.post_raw("ids/service/reconfigure", json!({}))?;
    let status = v.get("status").and_then(Value::as_str).unwrap_or("");
    if !status.is_empty() && !status.eq_ignore_ascii_case("ok") {
        bail!("Suricata reload reported: {v}");
    }
    Ok(())
}

/// Create or update the policy from a plan, then reload Suricata.
pub fn apply(api: &OPNsense, plan: &Plan) -> Result<String> {
    if plan.selected.is_empty() {
        bail!("No enabled high-risk rulesets matched - nothing to apply.");
    }
    let (path, verb) = match &plan.existing {
        Some(uuid) => (format!("ids/settings/set_policy/{uuid}"), "Updated"),
        None => ("ids/settings/add_policy".to_string(), "Created"),
    };
    check_saved(&api.post_raw(&path, plan.payload())?, "The policy")?;
    reconfigure(api)?;
    let msg = format!(
        "{verb} policy \"{POLICY_DESCRIPTION}\": {} rulesets, {} rules now Drop. Suricata reloaded.",
        plan.selected.len(),
        plan.total_changes()
    );
    log::warn!("{msg}");
    Ok(msg)
}

/// Delete our policy (rules go back to their defaults) and reload Suricata.
pub fn remove(api: &OPNsense) -> Result<String> {
    let (Some(uuid), _) = find_policy(api)? else {
        return Ok(format!("There is no \"{POLICY_DESCRIPTION}\" policy on the firewall."));
    };
    check_saved(&api.post_raw(&format!("ids/settings/del_policy/{uuid}"), json!({}))?, "Removing the policy")?;
    reconfigure(api)?;
    let msg = format!("Removed policy \"{POLICY_DESCRIPTION}\"; rules are back to their defaults. Suricata reloaded.");
    log::warn!("{msg}");
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names() {
        assert_eq!(base_name("et_open.emerging-exploit.rules"), "emerging-exploit");
        assert_eq!(base_name("emerging-exploit.rules"), "emerging-exploit");
        assert_eq!(base_name("abuse.ch.threatfox.rules"), "abuse.ch.threatfox");
        assert_eq!(base_name("snort_vrt.malware-cnc.rules"), "snort_vrt.malware-cnc");
    }

    #[test]
    fn payload_shape() {
        let p = Plan {
            mode: "Netmap (IPS)".into(),
            ips_on: true,
            interfaces: "wan".into(),
            existing: None,
            selected: vec![RulesetPlan { filename: "a.rules".into(), uuid: "u1".into(), rules: 5, alert_rules: 5 }],
            not_enabled: vec![],
            empty: vec![],
            not_installed: vec![],
            other_policies: 0,
        };
        let v = p.payload();
        assert_eq!(v["policy"]["new_action"], "drop");
        assert_eq!(v["policy"]["action"], "alert");
        assert_eq!(v["policy"]["rulesets"], "u1");
        assert!(p.render().contains("CREATED"));
    }
}
