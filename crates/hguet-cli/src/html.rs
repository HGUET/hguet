//! Standalone, passive HTML projection of engine-generated reports.
use hguet_core::sha256_hex;
use serde::Serialize;
use serde_json::Value;
use std::fmt::Write as _;

const CSS: &str = include_str!("report.css");

fn escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                let _ = write!(out, "\\u{{{:04X}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "Not available / not applicable".into(),
        Value::String(s) => escape(s),
        _ => escape(&value.to_string()),
    }
}

fn evidence_id(pointer: &str) -> String {
    format!("e-{}", sha256_hex(pointer.as_bytes()))
}

fn child_path(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn evidence_link(out: &mut String, root: &Value, pointer: &str, label: &str) {
    if root.pointer(pointer).is_some() {
        let _ = write!(
            out,
            "<a class=\"evidence-link\" href=\"#{}\">{}</a>",
            evidence_id(pointer),
            escape(label)
        );
    }
}

fn heading(out: &mut String, title: &str) {
    let _ = write!(out, "<h2>{}</h2>", escape(title));
}

fn field(out: &mut String, label: &str, value: &Value) {
    let _ = write!(
        out,
        "<div class=\"field\"><dt>{}</dt><dd>{}</dd></div>",
        escape(label),
        text(value)
    );
}

fn table(out: &mut String, rows: &Value, fields: &[(&str, &str)]) {
    let Some(rows) = rows.as_array() else {
        out.push_str("<p class=\"muted\">Data not available.</p>");
        return;
    };
    if rows.is_empty() {
        out.push_str("<p class=\"muted\">No rows reported in this view. This is not a safety conclusion.</p>");
        return;
    }
    out.push_str("<div class=\"table-scroll\"><table><thead><tr>");
    for (label, _) in fields {
        let _ = write!(out, "<th scope=\"col\">{}</th>", escape(label));
    }
    out.push_str("</tr></thead><tbody>");
    for row in rows {
        out.push_str("<tr>");
        for (_, pointer) in fields {
            let _ = write!(
                out,
                "<td>{}</td>",
                text(row.pointer(pointer).unwrap_or(&Value::Null))
            );
        }
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table></div>");
}

fn endpoint(value: &Value) -> String {
    if value.is_null() {
        return "Not applicable / not available".into();
    }
    if let Some(address) = value["address"].as_str() {
        escape(address)
    } else {
        format!("Unresolved account #{}", text(&value["message_index"]))
    }
}

fn flows(out: &mut String, root: &Value, flow: &Value, prefix: &str) {
    heading(out, "Declared asset movements");
    out.push_str("<p class=\"muted\">Original wire only. Raw quantities are not executed transfers or wallet losses. Do not combine with CPI or balance deltas.</p>");
    table(
        out,
        &flow["asset_totals"],
        &[
            ("Asset", "/asset/kind"),
            ("Mint", "/asset/mint"),
            ("Token program", "/asset/token_program"),
            ("Gross declared debit", "/declared_debit_raw"),
            ("Minted", "/declared_mint_raw"),
            ("Burned", "/declared_burn_raw"),
            ("Expected token fee", "/declared_expected_fee_raw"),
        ],
    );
    if let Some(rows) = flow["flows"].as_array() {
        for row in rows {
            out.push_str("<article class=\"movement\"><div class=\"movement-head\">");
            let _ = write!(
                out,
                "<strong>Instruction #{} · {}</strong><span>Raw amount: {}</span></div>",
                text(&row["instruction_index"]),
                text(&row["operation"]),
                text(&row["amount_raw"])
            );
            let _ = write!(
                out,
                "<div class=\"edge\"><div><small>From</small><code>{}</code></div><span class=\"arrow\" aria-hidden=\"true\">&#8594;</span><div><small>To</small><code>{}</code></div></div>",
                endpoint(&row["from"]),
                endpoint(&row["to"])
            );
            out.push_str("<dl class=\"fields\">");
            field(out, "Asset kind", &row["asset"]["kind"]);
            field(out, "Mint", &row["asset"]["mint"]);
            field(out, "Expected fee (raw, not extra debit)", &row["expected_fee_raw"]);
            out.push_str("</dl>");
            if let Some(pointer) = row["evidence_ref"].as_str() {
                evidence_link(out, root, &format!("{prefix}{pointer}"), "Original instruction evidence");
            }
            out.push_str("</article>");
        }
    }
    out.push_str("<dl class=\"fields\">");
    field(out, "Unknown asset instructions", &flow["unknown_asset_instruction_indices"]);
    field(out, "Unresolved endpoints", &flow["unresolved_endpoint_instruction_indices"]);
    field(out, "Unquantified instructions", &flow["unquantified_instruction_indices"]);
    out.push_str("</dl>");
}

fn authorities(out: &mut String, root: &Value, report: &Value, prefix: &str) {
    heading(out, "Declared authority changes");
    out.push_str("<p class=\"muted\">Potential control changes, not verified permissions. Delegate limits are not debits or additive allowances.</p>");
    table(
        out,
        &report["changes"],
        &[
            ("Instruction", "/instruction_index"),
            ("Scope", "/control_scope"),
            ("Action", "/action"),
            ("Target", "/target"),
            ("Proposed authority", "/proposed_authority"),
            ("Delegate limit (raw)", "/declared_delegate_limit_raw"),
            ("Hook", "/proposed_hook_program"),
        ],
    );
    if let Some(rows) = report["changes"].as_array() {
        for row in rows {
            if let Some(pointer) = row["evidence_ref"].as_str() {
                evidence_link(out, root, &format!("{prefix}{pointer}"), &format!("Instruction #{} evidence", row["instruction_index"]));
            }
        }
    }
    out.push_str("<dl class=\"fields\">");
    field(out, "Unclassified instructions", &report["unclassified_instruction_indices"]);
    out.push_str("</dl>");
}

fn programs(out: &mut String, root: &Value, report: &Value, prefix: &str) {
    heading(out, "Program inventory");
    out.push_str("<p class=\"muted\">A decoded declaration describes supported wire fields, not runtime validity.</p>");
    table(
        out,
        &report["instructions"],
        &[
            ("Instruction", "/instruction_index"),
            ("Family", "/family"),
            ("Program ID", "/program_id"),
            ("Layout", "/layout_status"),
            ("Declaration", "/declaration/kind"),
            ("Operation", "/declaration/operation"),
        ],
    );
    if let Some(rows) = report["instructions"].as_array() {
        for (i, _) in rows.iter().enumerate() {
            evidence_link(out, root, &format!("{prefix}/instructions/{i}"), &format!("Instruction #{i}"));
        }
    }
}

fn rpc_observations(out: &mut String, evidence: &Value, historical: bool) {
    heading(out, if historical { "Historical provider observations" } else { "Advisory simulation observations" });
    out.push_str("<p class=\"muted\">Single-provider metadata is untrusted. No independent execution proof. Missing data is not zero.</p>");
    if evidence.is_null() {
        out.push_str("<p>Provider evidence not available.</p>");
        return;
    }
    out.push_str("<dl class=\"fields\">");
    field(out, "Status", &evidence["status"]);
    if historical {
        field(out, "Reported slot", &evidence["slot"]);
        field(out, "Reported fee (lamports)", &evidence["reported_fee_lamports"]);
        field(out, "Effects status", &evidence["effects_status"]);
    } else {
        field(out, "Simulation slot", &evidence["context_slot"]);
        field(out, "Simulated fee (lamports)", &evidence["effect_analysis"]["simulated_fee_lamports"]);
    }
    out.push_str("</dl>");
    let effects = if historical { &evidence["effects"] } else { &evidence["effect_analysis"] };
    out.push_str("<h3>Native net balance rows</h3>");
    table(out, &effects["lamport_deltas"], &[("Account", "/address"), ("Before", "/before_lamports"), ("After", "/after_lamports"), ("Delta (lamports)", "/delta_lamports")]);
    out.push_str("<h3>Token net balance rows</h3>");
    table(out, &effects["token_deltas"], &[("Account", "/token_account"), ("Mint", "/mint"), ("Before", "/before_raw_amount"), ("After", "/after_raw_amount"), ("Delta (raw)", "/delta_raw_amount"), ("Complete pair", "/complete_pair")]);
    out.push_str("<h3>Reported CPI token instructions</h3>");
    table(out, &effects["cpi"]["token_instructions"], &[("Parent", "/parent_instruction_index"), ("Inner", "/inner_instruction_index"), ("Operation", "/operation"), ("Amount (raw)", "/amount_raw")]);
}

fn diff(out: &mut String, root: &Value) {
    heading(out, "Transaction comparison");
    out.push_str("<p class=\"muted\">Position comparison, not edit alignment or semantic equivalence. Equal multisets do not prove equal execution.</p><div class=\"compare\">");
    for (side, label) in [("before", "Before"), ("after", "After")] {
        let _ = write!(out, "<article class=\"panel\"><h3>{label}</h3><dl class=\"fields\">");
        for (label, key) in [("Message hash", "message_sha256"), ("Fee payer", "fee_payer"), ("Format", "wire_format"), ("Signature status", "signature_status"), ("Coverage gaps", "coverage_gap_indices")] {
            field(out, label, &root[side][key]);
        }
        out.push_str("</dl></article>");
    }
    out.push_str("</div><dl class=\"fields\">");
    field(out, "Message fields changed", &root["message_fields_changed"]);
    field(out, "Instruction order equal", &root["ordered_instruction_fingerprints_equal"]);
    field(out, "Instruction multiset equal", &root["instruction_multiset_equal"]);
    out.push_str("</dl>");
    table(out, &root["instruction_changes"], &[("Before index", "/before_index"), ("After index", "/after_index"), ("Status", "/status"), ("Changed fields", "/changed_fields")]);
    if let Some(rows) = root["instruction_changes"].as_array() {
        for row in rows {
            out.push_str("<article class=\"panel\"><h3>Changed position</h3><div class=\"compare\">");
            for (key, label) in [("before_ref", "Before"), ("after_ref", "After")] {
                let _ = write!(out, "<div><h4>{label}</h4>");
                if let Some(pointer) = row[key].as_str() {
                    if let Some(ix) = root.pointer(pointer) {
                        out.push_str("<dl class=\"fields\">");
                        field(out, "Declaration", &ix["declaration"]);
                        field(out, "Asset movement", &ix["asset_movement"]);
                        field(out, "Authority change", &ix["authority_change"]);
                        out.push_str("</dl>");
                        evidence_link(out, root, pointer, "Instruction evidence");
                    }
                } else {
                    out.push_str("<p>Position absent</p>");
                }
                out.push_str("</div>");
            }
            out.push_str("</div></article>");
        }
    }
}

fn evidence_tree(out: &mut String, value: &Value, path: &str, label: &str, depth: usize) {
    let id = evidence_id(path);
    match value {
        Value::Object(map) => {
            let open = if depth < 2 { " open" } else { "" };
            let _ = write!(out, "<details id=\"{id}\"{open}><summary>{} · {} fields</summary>", escape(label), map.len());
            for (key, child) in map {
                evidence_tree(out, child, &child_path(path, key), key, depth + 1);
            }
            out.push_str("</details>");
        }
        Value::Array(rows) => {
            let open = if depth < 2 { " open" } else { "" };
            let _ = write!(out, "<details id=\"{id}\"{open}><summary>{} · {} rows</summary>", escape(label), rows.len());
            for (i, child) in rows.iter().enumerate() {
                evidence_tree(out, child, &child_path(path, &i.to_string()), &format!("#{i}"), depth + 1);
            }
            out.push_str("</details>");
        }
        _ => {
            let _ = write!(out, "<div class=\"evidence-value\" id=\"{id}\"><span>{}</span><code>{}</code></div>", escape(label), text(value));
        }
    }
}

/// Render only recognized engine report types; no network, external assets or scripts.
pub fn render<T: Serialize>(report: &T) -> Result<String, String> {
    let root = serde_json::to_value(report).map_err(|_| "report serialization failed")?;
    if root["schema_version"] != 1 || root["signing_authorization"] != "NOT_AUTHORIZED" {
        return Err("unsupported HTML report contract".into());
    }
    let kind = root["kind"].as_str().ok_or("missing report kind")?;
    let title = match kind {
        "hguet_transaction_report" => "Transaction Intelligence",
        "hguet_program_intelligence" => "Program Intelligence",
        "hguet_asset_flow" => "Asset Flow Intelligence",
        "hguet_authority_intelligence" => "Authority Intelligence",
        "hguet_transaction_diff" => "Semantic Transaction Diff",
        "hguet_rpc_asset_flow" => "RPC Asset Flow",
        "hguet_historical_audit" => "Historical Transaction Audit",
        _ => return Err("unsupported HTML report kind".into()),
    };
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; object-src 'none'\"><meta name=\"referrer\" content=\"no-referrer\"><title>HGUET · ");
    out.push_str(title);
    out.push_str("</title><style>");
    out.push_str(CSS);
    out.push_str("</style></head><body><main><header><p class=\"brand\">HGUET / COMMUNITY EDITION</p><p class=\"eyebrow\">SOLANA TRANSACTION INTELLIGENCE · DEVELOPER PREVIEW</p><h1>");
    out.push_str(title);
    out.push_str("</h1><p class=\"boundary\">Signing authorization: NOT_AUTHORIZED</p><p>Read-only evidence report. Not a safety certificate or proof of execution.</p><nav aria-label=\"Report sections\"><a href=\"#analysis\">Analysis</a><a href=\"#limitations\">Limitations</a><a href=\"#evidence\">Evidence</a></nav></header><section id=\"analysis\"><dl class=\"fields\">");
    for (label, key) in [("Message hash", "message_sha256"), ("Status", "status"), ("Relation", "relation"), ("Network", "network"), ("Signature", "signature"), ("RPC error", "rpc_error")] {
        if let Some(value) = root.get(key) {
            field(&mut out, label, value);
        }
    }
    out.push_str("</dl>");
    match kind {
        "hguet_transaction_report" => {
            flows(&mut out, &root, &root["wire"], "/wire");
            authorities(&mut out, &root, &root["authority"], "/authority");
            programs(&mut out, &root, &root["wire"]["program_report"], "/wire/program_report");
        }
        "hguet_program_intelligence" => programs(&mut out, &root, &root, ""),
        "hguet_asset_flow" => {
            flows(&mut out, &root, &root, "");
            programs(&mut out, &root, &root["program_report"], "/program_report");
        }
        "hguet_authority_intelligence" => {
            authorities(&mut out, &root, &root, "");
            programs(&mut out, &root, &root["program_report"], "/program_report");
        }
        "hguet_transaction_diff" => diff(&mut out, &root),
        "hguet_rpc_asset_flow" | "hguet_historical_audit" => {
            if !root["wire"].is_null() {
                flows(&mut out, &root, &root["wire"], "/wire");
                programs(&mut out, &root, &root["wire"]["program_report"], "/wire/program_report");
            }
            if kind == "hguet_historical_audit" {
                if !root["authority"].is_null() {
                    authorities(&mut out, &root, &root["authority"], "/authority");
                }
                rpc_observations(&mut out, &root["historical"], true);
            } else {
                rpc_observations(&mut out, &root["rpc_evidence"], false);
                heading(&mut out, "Evidence correlation");
                table(&mut out, &root["endpoint_links"], &[("Instruction", "/instruction_index"), ("Endpoint", "/endpoint_role"), ("Match status", "/status")]);
            }
        }
        _ => unreachable!("checked report kind"),
    }
    out.push_str("</section><section id=\"limitations\"><h2>Scope &amp; limitations</h2><ul>");
    if let Some(items) = root["limitations"].as_array() {
        for item in items {
            let _ = write!(out, "<li>{}</li>", text(item));
        }
    }
    out.push_str("</ul><p>Additional limitations of nested views are preserved below.</p></section><section id=\"evidence\"><h2>Evidence explorer</h2><p class=\"muted\">Expand fields to inspect the exact report values. Links identify rows; expand parent groups if needed. Null never implies zero.</p>");
    evidence_tree(&mut out, &root, "", "Engine report", 0);
    out.push_str("</section><footer>HGUET · Local-first · No signing or broadcast · MIT</footer></main></body></html>");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn untrusted_values_never_become_markup() {
        let payload = "</code><script>alert(1)</script><img src=x onerror=alert(2)> & \" ' \u{202e}";
        let report = json!({
            "schema_version":1,"kind":"hguet_program_intelligence",
            "signing_authorization":"NOT_AUTHORIZED",
            "message_sha256":payload,"instructions":[],
            "limitations":[payload]
        });
        let html = render(&report).unwrap();
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains('\u{202e}'));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("\\u{202E}"));
        assert!(html.contains("default-src 'none'"));
    }

    #[test]
    fn evidence_links_use_resolved_local_hash_anchors() {
        let report = json!({
            "schema_version":1,"kind":"hguet_program_intelligence",
            "signing_authorization":"NOT_AUTHORIZED",
            "instructions":[{"instruction_index":0,"family":"<unsafe>","declaration":{"kind":"unsupported"}}],
            "limitations":[]
        });
        let html = render(&report).unwrap();
        let id = evidence_id("/instructions/0");
        assert!(html.contains(&format!("href=\"#{id}\"")));
        assert!(html.contains(&format!("id=\"{id}\"")));
        assert!(!html.contains("<unsafe>"));
    }

    #[test]
    fn only_known_non_authorizing_envelopes_render() {
        assert!(render(&json!({"kind":"arbitrary","schema_version":1,
            "signing_authorization":"NOT_AUTHORIZED"})).is_err());
        assert!(render(&json!({"kind":"hguet_asset_flow","schema_version":1,
            "signing_authorization":"AUTHORIZED"})).is_err());
    }
}
