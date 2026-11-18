//! A settings-style view of already-authorized diagnostic evidence.
use super::*;
use radius_management::diagnostics::{Attempt, Record as DiagnosticRecord, OPERATION, STAGE};

fn value(record: &DiagnosticRecord, key: &str) -> String {
    match record.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(value) => value.to_string(),
        None => "Unavailable".into(),
    }
}
fn result(attempt: &Attempt) -> String {
    if !attempt.outcome_available {
        return "Outcome unavailable".into();
    }
    match attempt
        .summary
        .get("outcome.success")
        .and_then(serde_json::Value::as_bool)
    {
        Some(true) => "Accept submitted".into(),
        Some(false) => attempt
            .summary
            .get("outcome.reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Unsuccessful")
            .into(),
        None => "Outcome unavailable".into(),
    }
}
impl Window {
    pub(super) fn diagnostic_filter(
        &self,
        fields: &Fields,
    ) -> io::Result<radius_management::diagnostics::Filter> {
        let mut args = Vec::new();
        for (field, flag) in [
            ("diag-since", "--since"),
            ("diag-network", "--network"),
            ("diag-client", "--client"),
            ("diag-user", "--username"),
            ("diag-station", "--station"),
        ] {
            if !fields.get(field).is_empty() {
                args.push(flag);
                args.push(fields.get(field));
            }
        }
        crate::cli::diagnostic_filter(&args)
    }
    pub(super) fn diagnostics_page(&self) -> String {
        let view = &self.diagnostics;
        let mut page = String::new();
        let mut filters = String::new();
        for (field, title, help, kind) in [
            (
                "diag-since",
                "Lookback",
                "Seconds; empty uses the configured default.",
                "number",
            ),
            (
                "diag-network",
                "Network",
                "Access-policy GUID; empty includes all readable networks.",
                "text",
            ),
            (
                "diag-client",
                "Client",
                "Client configuration GUID.",
                "text",
            ),
            (
                "diag-user",
                "Supplied Username",
                "Unverified inner username, matched exactly.",
                "text",
            ),
            (
                "diag-station",
                "Station",
                "AP-reported address in aa:bb:cc:dd:ee:ff form.",
                "text",
            ),
        ] {
            filters.push_str(&settings::row(
                title,
                help,
                &text(field, title, kind, !self.busy),
            ));
        }
        page.push_str(&format!(
            "<form fx-submit=\"diagnostics-follow\">{}{}</form>",
            settings::group("Find Attempts", &filters, ""),
            settings::actions(&format!(
                "{}{}{}",
                settings::submit("Follow Live", Button::Primary, !self.busy),
                settings::button(
                    "Refresh History",
                    "diagnostics-refresh",
                    &[],
                    Button::Plain,
                    !self.busy
                ),
                settings::button(
                    "Stop Following",
                    "diagnostics-stop",
                    &[],
                    Button::Plain,
                    self.diagnostic_monitor.is_some()
                )
            ))
        ));
        let mut health = settings::fact(
            "Event Reader",
            if view.status.is_empty() {
                "Choose Follow Live or Refresh History"
            } else {
                &view.status
            },
            false,
        );
        health.push_str(&settings::fact(
            "Collection",
            if view.collection.is_empty() {
                "Not confirmed by readable collection reports"
            } else {
                "Readable collection reports available"
            },
            false,
        ));
        if view.possible_gap {
            health.push_str(&settings::fact(
                "Evidence",
                "A collection interruption may have left gaps",
                false,
            ));
        }
        if view.truncated {
            health.push_str(&settings::fact(
                "Result Limit",
                "Some records or details were omitted by configured limits",
                false,
            ));
        }
        if view.uncorrelated > 0 {
            health.push_str(&settings::fact(
                "Unlinked Records",
                &format!(
                    "{} readable records lack usable attempt correlation",
                    view.uncorrelated
                ),
                false,
            ));
        }
        if let Some(last) = view.collection.last() {
            for (key, label) in [
                ("object.radiusd.diagnostics.failed", "Emission Failures"),
                (
                    "object.radiusd.diagnostics.suppressed",
                    "Rate-Limited Records",
                ),
                (
                    "object.radiusd.diagnostics.disabled",
                    "Records Disabled by Emission Policy",
                ),
            ] {
                health.push_str(&settings::fact(label, &value(last, key), false));
            }
        }
        page.push_str(&settings::group("Collection Status", &health, ""));
        let mut rows = String::new();
        for attempt in &view.attempts {
            let name = if let Some(name) = attempt
                .summary
                .get("object.radiusd.canonical-name")
                .and_then(serde_json::Value::as_str)
            {
                name.to_owned()
            } else if let Some(name) = attempt
                .summary
                .get("source.radiusd.username")
                .and_then(serde_json::Value::as_str)
            {
                format!("{name} (supplied)")
            } else {
                "Identity unavailable".into()
            };
            rows.push_str(&settings::row(
                &name,
                &format!(
                    "{} · {} · {} · {}",
                    attempt.id,
                    radius_management::diagnostics::age(&attempt.summary),
                    value(&attempt.summary, "object.radiusd.method"),
                    result(attempt)
                ),
                &settings::button(
                    "Details",
                    "diagnostics-select",
                    &[("id", &attempt.id)],
                    Button::Plain,
                    !self.busy,
                ),
            ));
        }
        if rows.is_empty() {
            rows = settings::fact(
                "Attempts",
                "No matching readable records in the returned window",
                false,
            );
        }
        page.push_str(&settings::group("Authentication Attempts", &rows, ""));
        if let Some(selected) = &self.diagnostic_selected {
            if let Some(attempt) = view.attempts.iter().find(|a| &a.id == selected) {
                let mut rows = settings::fact("Attempt", selected, true);
                rows.push_str(&settings::fact("RADIUS Outcome", &result(attempt), false));
                rows.push_str(&settings::fact(
                    "Connection",
                    "An Accept does not confirm AP admission, DHCP or internet access",
                    false,
                ));
                if attempt.possible_gap {
                    rows.push_str(&settings::fact(
                        "Timeline",
                        "Some stages may be unavailable",
                        false,
                    ));
                }
                for (field, label) in [
                    ("source.radiusd.username", "Supplied Username (Unverified)"),
                    ("object.radiusd.canonical-name", "Verified Name"),
                    ("object.radiusd.client.name", "Recorded Client Name"),
                    ("object.radiusd.network.name", "Recorded Policy Name"),
                    (
                        "object.radiusd.authentication-profile.name",
                        "Recorded Authentication Profile Name",
                    ),
                    (
                        "object.radiusd.assignment.profile.name",
                        "Recorded Access Profile Name",
                    ),
                    ("object.radiusd.assignment.rule.name", "Recorded Rule Name"),
                    ("object.account.sid", "Verified SID"),
                    ("source.address", "Packet Source"),
                    ("source.radiusd.station", "AP-Reported Station"),
                    (
                        "object.radiusd.client.configuration-id",
                        "Client Configuration",
                    ),
                    ("object.radiusd.network.configuration-id", "Access Policy"),
                    (
                        "object.radiusd.config.fingerprint",
                        "Effective Configuration Fingerprint",
                    ),
                    (
                        "object.radiusd.authentication-profile.id",
                        "Authentication Profile",
                    ),
                    ("object.radiusd.assignment.rule.id", "Recorded Winning Rule"),
                    (
                        "object.radiusd.assignment.profile.id",
                        "Recorded Access Profile",
                    ),
                    ("object.radiusd.assignment.vlan", "Recorded VLAN"),
                    ("outcome.detail", "Decision Detail"),
                    ("object.radiusd.reply", "Reply Submission"),
                    ("event.boot.guid", "Recorded Boot"),
                    ("emitter.class", "Kernel Emitter Class"),
                    ("emitter.process.guid", "Kernel Emitter Process"),
                    ("emitter.token.guid", "Kernel Emitter Token"),
                    ("emitter.true-token.guid", "Kernel Emitter Primary Token"),
                    (OPERATION, "authd Operation"),
                ] {
                    rows.push_str(&settings::fact(
                        label,
                        &value(&attempt.summary, field),
                        true,
                    ));
                }
                page.push_str(&settings::group("Recorded Decision", &rows, ""));
                let mut current = String::new();
                for (field, kind, section, label) in [
                    (
                        "object.radiusd.client.configuration-id",
                        Kind::Client,
                        "client",
                        "Client",
                    ),
                    (
                        "object.radiusd.network.configuration-id",
                        Kind::Policy,
                        "policy",
                        "Access Policy",
                    ),
                    (
                        "object.radiusd.authentication-profile.id",
                        Kind::Profile,
                        "profile",
                        "Authentication Profile",
                    ),
                    (
                        "object.radiusd.assignment.profile.id",
                        Kind::AccessProfile,
                        "access-profile",
                        "Access Profile",
                    ),
                    (
                        "object.radiusd.assignment.rule.id",
                        Kind::Rule,
                        "rule",
                        "Winning Rule",
                    ),
                ] {
                    let Some(id) = attempt
                        .summary
                        .get(field)
                        .and_then(serde_json::Value::as_str)
                    else {
                        continue;
                    };
                    let readable = self
                        .stored
                        .as_ref()
                        .ok()
                        .and_then(|s| s.get(kind, id))
                        .is_some();
                    current.push_str(&settings::row(
                        label,
                        "Present configuration; it may differ from the recorded decision.",
                        &settings::button(
                            "Open Current Object",
                            "diagnostics-current",
                            &[("id", id), ("section", section)],
                            Button::Plain,
                            readable && !self.busy,
                        ),
                    ));
                }
                if !current.is_empty() {
                    page.push_str(&settings::group("Current Configuration", &current, ""));
                }
                let mut timeline = String::new();
                for record in &attempt.stages {
                    timeline.push_str(&settings::row(
                        &value(record, STAGE),
                        &format!(
                            "{} ms · {}",
                            value(record, "object.radiusd.elapsed-ms"),
                            value(record, "object.radiusd.progress.result")
                        ),
                        "",
                    ));
                }
                page.push_str(&settings::group("Observed Timeline", &timeline, ""));
                if attempt
                    .summary
                    .get(OPERATION)
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                {
                    page.push_str(&settings::group(
                        "Authority Evidence",
                        &settings::row(
                            "authd Events",
                            "Read exact linked operation events using your eventd permissions.",
                            &settings::button(
                                "Read Linked Events",
                                "diagnostics-authority",
                                &[],
                                Button::Plain,
                                !self.busy,
                            ),
                        ),
                        "",
                    ));
                }
                if let Some(linked) = self
                    .diagnostic_authority
                    .as_ref()
                    .filter(|_| attempt.summary.contains_key(OPERATION))
                {
                    let body = match linked {
                        Ok(records) if records.is_empty() => {
                            settings::fact("authd", "No matching readable authority records", false)
                        }
                        Ok(records) => records
                            .iter()
                            .map(|r| {
                                settings::fact(
                                    "Recorded Authority Result",
                                    &serde_json::to_string_pretty(r).unwrap_or_default(),
                                    true,
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                        Err(error) => settings::banner(error),
                    };
                    page.push_str(&settings::group("Linked Authority Records", &body, ""));
                }
            } else {
                page.push_str(&settings::group(
                    "Selected Attempt",
                    &settings::fact(
                        selected,
                        "Unavailable in the current readable result window",
                        true,
                    ),
                    "",
                ));
            }
        }
        let mut drops = String::new();
        for record in view.drops.iter().rev().take(64) {
            drops.push_str(&settings::row(
                &value(record, "outcome.reason"),
                &format!(
                    "{} discarded requests · listener {} · sample source {} · matched client {}",
                    value(record, "object.radiusd.drops.count"),
                    value(record, "object.radiusd.listener-index"),
                    value(record, "source.address"),
                    value(record, "object.radiusd.client.configuration-id")
                ),
                "",
            ));
        }
        if drops.is_empty() {
            drops = settings::fact("Requests", "No matching readable drop reports", false);
        }
        page.push_str(&settings::group(
            "Dropped Before a Conversation",
            &drops,
            "",
        ));
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_management::diagnostics::View;
    #[test]
    fn missing_results_and_escaped_peer_text_are_not_rendered_as_success() {
        let mut w = super::super::tests::window();
        let summary = [(
            "source.radiusd.username".into(),
            "<script>peer</script>".into(),
        )]
        .into();
        w.diagnostics = View {
            attempts: vec![Attempt {
                id: "test".into(),
                summary,
                stages: vec![],
                outcome_available: false,
                possible_gap: true,
            }],
            ..Default::default()
        };
        w.diagnostic_selected = Some("test".into());
        let html = w.diagnostics_page();
        assert!(html.contains("Outcome unavailable"));
        assert!(!html.contains("<script>peer"));
        assert!(html.contains("&lt;script&gt;peer"));
        assert!(!html.contains("Accept submitted"));
    }
}
