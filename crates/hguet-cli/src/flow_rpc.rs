//! Read-only correlation of wire declarations with single-provider RPC claims.
use crate::flow::{self, Endpoint, FlowEdge, FlowReport};
use hguet_rpc::{JsonRpcTransport, SimulationEffects, SimulationEvidence};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct EndpointLink {
    pub instruction_index: usize,
    pub endpoint_role: &'static str,
    pub wire_ref: String,
    pub status: &'static str,
    pub observation_ref: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CpiLink {
    pub parent_instruction_index: usize,
    pub inner_instruction_index: usize,
    pub wire_ref: String,
    pub observation_ref: String,
}

#[derive(Debug, Serialize)]
pub struct RpcFlowReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub network: String,
    pub status: &'static str,
    pub rpc_error: Option<&'static str>,
    pub signing_authorization: &'static str,
    pub execution_proven: bool,
    pub wire: FlowReport,
    pub rpc_evidence: Option<SimulationEvidence>,
    pub endpoint_links: Vec<EndpointLink>,
    pub cpi_links: Vec<CpiLink>,
    pub limitations: Vec<&'static str>,
}

fn match_endpoint(
    edge: &FlowEdge,
    endpoint: &Endpoint,
    effects: Option<&SimulationEffects>,
) -> (&'static str, Option<String>) {
    let Some(address) = endpoint.address.as_ref() else {
        return ("UNRESOLVED_WIRE_ADDRESS", None);
    };
    let Some(effects) = effects else {
        return ("RPC_UNAVAILABLE", None);
    };
    if edge.asset.kind == "sol" {
        let Some(rows) = effects.lamport_deltas.as_ref() else {
            return ("METADATA_ABSENT", None);
        };
        return match rows
            .iter()
            .position(|r| r.account_index == endpoint.message_index && r.address == *address)
        {
            Some(i) => (
                "ACCOUNT_ROW_MATCH",
                Some(format!("/rpc_evidence/effect_analysis/lamport_deltas/{i}")),
            ),
            // The decoder omits unchanged native accounts. Do not invent a
            // zero execution amount or attribute a delta to this instruction.
            None => ("NO_DELTA_ROW", None),
        };
    }
    let Some(mint) = edge.asset.mint.as_ref() else {
        return ("UNKNOWN_WIRE_MINT", None);
    };
    let Some(rows) = effects.token_deltas.as_ref() else {
        return ("METADATA_ABSENT", None);
    };
    match rows.iter().enumerate().find(|(_, r)| {
        r.account_index == endpoint.message_index && r.token_account == *address && r.mint == *mint
    }) {
        Some((i, row)) => (
            if row.complete_pair {
                "ACCOUNT_MINT_ROW_MATCH"
            } else {
                "INCOMPLETE_ACCOUNT_MINT_ROW"
            },
            Some(format!("/rpc_evidence/effect_analysis/token_deltas/{i}")),
        ),
        None => ("NO_DELTA_ROW", None),
    }
}

/// Explicit transport, network and endpoint. Invalid wire never reaches RPC.
/// RPC failure preserves the independently decoded wire view.
pub fn inspect<T: JsonRpcTransport>(
    bytes: &[u8],
    network: &str,
    endpoint: &str,
    transport: &T,
) -> Result<RpcFlowReport, String> {
    let wire = flow::inspect(bytes)?;
    hguet_rpc::validate_endpoint(endpoint).map_err(|e| e.code().to_owned())?;
    hguet_rpc::expected_genesis(network).map_err(|e| e.code().to_owned())?;
    let (status, rpc_error, rpc_evidence) =
        match hguet_rpc::simulate_with(transport, endpoint, network, bytes) {
            Ok(evidence) if evidence.simulated_message_sha256 == wire.message_sha256 => {
                let status = if evidence.status == "rpc_succeeded" {
                    "RPC_SIMULATION_SUCCEEDED"
                } else {
                    "RPC_SIMULATION_FAILED"
                };
                (status, None, Some(evidence))
            }
            Ok(_) => ("RPC_UNAVAILABLE", Some("MESSAGE_BINDING_MISMATCH"), None),
            Err(error) => ("RPC_UNAVAILABLE", Some(error.code()), None),
        };
    let effects = rpc_evidence.as_ref().map(|e| &e.effect_analysis);
    let mut endpoint_links = Vec::new();
    for (i, edge) in wire.flows.iter().enumerate() {
        for (role, endpoint) in [("from", &edge.from), ("to", &edge.to)] {
            if let Some(endpoint) = endpoint {
                let (status, observation_ref) = match_endpoint(edge, endpoint, effects);
                endpoint_links.push(EndpointLink {
                    instruction_index: edge.instruction_index,
                    endpoint_role: role,
                    wire_ref: format!("/wire/flows/{i}/{role}"),
                    status,
                    observation_ref,
                });
            }
        }
    }
    let mut cpi_links = Vec::new();
    if let Some(effects) = effects {
        for (i, item) in effects.cpi.token_instructions.iter().enumerate() {
            cpi_links.push(CpiLink {
                parent_instruction_index: item.parent_instruction_index,
                inner_instruction_index: item.inner_instruction_index,
                wire_ref: format!(
                    "/wire/program_report/instructions/{}",
                    item.parent_instruction_index
                ),
                observation_ref: format!(
                    "/rpc_evidence/effect_analysis/cpi/token_instructions/{i}"
                ),
            });
        }
        for (i, item) in effects
            .cpi
            .token_2022_extension_observations
            .iter()
            .enumerate()
        {
            cpi_links.push(CpiLink {
                parent_instruction_index: item.parent_instruction_index,
                inner_instruction_index: item.inner_instruction_index,
                wire_ref: format!(
                    "/wire/program_report/instructions/{}",
                    item.parent_instruction_index
                ),
                observation_ref: format!(
                    "/rpc_evidence/effect_analysis/cpi/token_2022_extension_observations/{i}"
                ),
            });
        }
    }
    Ok(RpcFlowReport {
        schema_version: 1,
        kind: "hguet_rpc_asset_flow",
        network: network.to_owned(),
        status,
        rpc_error,
        signing_authorization: "NOT_AUTHORIZED",
        execution_proven: false,
        wire,
        rpc_evidence,
        endpoint_links,
        cpi_links,
        limitations: vec![
            "RPC data is one provider's advisory simulation, not observed on-chain execution.",
            "Original wire is preserved; replacement blockhash and disabled signature verification limit simulation.",
            "Links match account indices, addresses and declared mint, not amounts, ownership, causality or authorization.",
            "Token delta rows do not retain token program identity; a mint row match is not a program match.",
            "Repeated links can point at one net delta; never sum links or add them to wire totals.",
            "CPI links are reported parent relationships, not proof of completeness or execution.",
            "Lookup resolution and later account and mint snapshots are non-atomic and untrusted.",
            "No actual fee, total spending, safe-signing or policy conclusion is inferred.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hguet_rpc::RpcError;
    use serde_json::{json, Value};
    use std::cell::Cell;

    struct Fake {
        body: Value,
        calls: Cell<usize>,
        unavailable: bool,
    }

    impl JsonRpcTransport for Fake {
        fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
            self.calls.set(self.calls.get() + 1);
            if self.unavailable {
                return Err(RpcError::Transport);
            }
            match request["method"].as_str() {
                Some("getGenesisHash") => Ok(json!({
                    "jsonrpc":"2.0","id":1,
                    "result":hguet_rpc::expected_genesis("devnet").unwrap()
                })),
                Some("simulateTransaction") => {
                    assert_eq!(request["params"][1]["sigVerify"], false);
                    assert_eq!(request["params"][1]["replaceRecentBlockhash"], true);
                    Ok(json!({
                        "jsonrpc":"2.0","id":2,
                        "result":{"context":{"slot":1234},"value":self.body}
                    }))
                }
                Some("getMultipleAccounts") => {
                    let count = request["params"][0].as_array().unwrap().len();
                    Ok(json!({
                        "jsonrpc":"2.0","id":request["id"],
                        "result":{"context":{"slot":1235},"value":vec![Value::Null; count]}
                    }))
                }
                _ => panic!("unexpected RPC call"),
            }
        }
    }

    fn fixture() -> Vec<u8> {
        STANDARD
            .decode(include_str!("../../../tests/fixtures/v1-system-transfer.base64").trim())
            .unwrap()
    }

    fn provider(body: Value) -> Fake {
        Fake {
            body,
            calls: Cell::new(0),
            unavailable: false,
        }
    }

    #[test]
    fn wire_and_rpc_net_rows_remain_separate() {
        let bytes = fixture();
        let wire = flow::inspect(&bytes).unwrap();
        let edge = &wire.flows[0];
        let from = edge.from.as_ref().unwrap().message_index;
        let to = edge.to.as_ref().unwrap().message_index;
        let count = hguet_core::parse_transaction(&bytes)
            .unwrap()
            .total_address_count;
        let before = vec![10_000u64; count];
        let mut after = before.clone();
        after[from] -= 700;
        after[to] += 500;
        let fake = provider(json!({
            "err":null,"preBalances":before,"postBalances":after,
            "innerInstructions":[],"fee":200
        }));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &fake).unwrap();
        assert_eq!(fake.calls.get(), 2);
        assert_eq!(report.status, "RPC_SIMULATION_SUCCEEDED");
        assert_eq!(report.wire.asset_totals[0].declared_debit_raw, "500");
        assert!(!report.execution_proven);
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
        let html = crate::html::render(&report).unwrap();
        assert!(html.contains("Advisory simulation observations"));
        assert!(html.contains("Original instruction evidence"));
        assert!(html.contains("NOT_AUTHORIZED"));
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(
            value["rpc_evidence"]["effect_analysis"]["simulated_fee_lamports"],
            "200"
        );
        assert!(value["wire"]["actual_network_fee_lamports"].is_null());
        for link in value["endpoint_links"].as_array().unwrap() {
            assert_eq!(link["status"], "ACCOUNT_ROW_MATCH");
            for field in ["wire_ref", "observation_ref"] {
                assert!(value.pointer(link[field].as_str().unwrap()).is_some());
            }
        }
    }

    #[test]
    fn absent_and_empty_metadata_are_not_interchangeable() {
        let bytes = fixture();
        let missing = provider(json!({"err":null}));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &missing).unwrap();
        assert!(report
            .endpoint_links
            .iter()
            .all(|l| l.status == "METADATA_ABSENT"));
        let count = hguet_core::parse_transaction(&bytes)
            .unwrap()
            .total_address_count;
        let balances = vec![1000u64; count];
        let unchanged = provider(json!({
            "err":null,"preBalances":balances,"postBalances":balances
        }));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &unchanged).unwrap();
        assert!(report
            .endpoint_links
            .iter()
            .all(|l| l.status == "NO_DELTA_ROW"));
        assert_eq!(report.wire.asset_totals[0].declared_debit_raw, "500");
    }

    #[test]
    fn failed_and_unavailable_simulation_retain_wire() {
        let bytes = fixture();
        let failed = provider(json!({"err":{"InstructionError":[0,1]}}));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &failed).unwrap();
        assert_eq!(report.status, "RPC_SIMULATION_FAILED");
        assert!(report.rpc_evidence.is_some());
        assert!(!report.execution_proven);
        // Long, non-ASCII provider errors must not panic during truncation.
        let unicode_error = provider(json!({"err":"é".repeat(1024)}));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &unicode_error).unwrap();
        assert_eq!(report.status, "RPC_SIMULATION_FAILED");
        assert!(report.rpc_evidence.unwrap().error_summary.unwrap().len() <= 1024);
        let mut unavailable = provider(Value::Null);
        unavailable.unavailable = true;
        let report = inspect(&bytes, "devnet", "https://rpc.example", &unavailable).unwrap();
        assert_eq!(report.status, "RPC_UNAVAILABLE");
        assert!(report.rpc_evidence.is_none());
        assert_eq!(report.wire.asset_totals[0].declared_debit_raw, "500");
        assert_eq!(report.rpc_error, Some("RPC_TRANSPORT_FAILURE"));
    }

    #[test]
    fn repeated_wire_edges_link_to_one_net_observation_without_merging_totals() {
        let mut bytes = vec![1];
        bytes.extend([0; 64]);
        bytes.extend([1, 0, 1, 3]);
        bytes.extend([7; 32]);
        bytes.extend([8; 32]);
        bytes.extend([0; 32]);
        bytes.extend([9; 32]);
        bytes.push(2);
        for amount in [300u64, 201] {
            bytes.extend([2, 2, 0, 1, 12, 2, 0, 0, 0]);
            bytes.extend(amount.to_le_bytes());
        }
        let fake = provider(json!({
            "err":null,"preBalances":[10000,1000,1],"postBalances":[9499,1501,1]
        }));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &fake).unwrap();
        assert_eq!(report.wire.flows.len(), 2);
        assert_eq!(report.wire.asset_totals[0].declared_debit_raw, "501");
        assert_eq!(report.endpoint_links.len(), 4);
        assert_eq!(
            report.endpoint_links[0].observation_ref,
            report.endpoint_links[2].observation_ref
        );
        assert_eq!(
            report.endpoint_links[1].observation_ref,
            report.endpoint_links[3].observation_ref
        );
        assert_eq!(
            report
                .rpc_evidence
                .unwrap()
                .effect_analysis
                .lamport_deltas
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn token_balance_pairs_and_cpi_claims_are_independent() {
        let bytes = STANDARD
            .decode(
                include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64").trim(),
            )
            .unwrap();
        let wire = flow::inspect(&bytes).unwrap();
        let edge = &wire.flows[0];
        let mint = edge.asset.mint.as_ref().unwrap();
        let from = edge.from.as_ref().unwrap().message_index;
        let to = edge.to.as_ref().unwrap().message_index;
        let parsed = hguet_core::parse_transaction(&bytes).unwrap();
        let instruction = &parsed.compiled_top_level_instructions[0];
        let row = |index, amount| {
            json!({"accountIndex":index,"mint":mint,
                "uiTokenAmount":{"amount":amount,"decimals":6}})
        };
        let fake = provider(json!({
            "err":null,
            "preTokenBalances":[row(from,"2000")],
            "postTokenBalances":[row(from,"766"),row(to,"1234")],
            "innerInstructions":[{"index":0,"instructions":[{
                "programIdIndex":instruction.program_index,
                "accounts":instruction.account_indices,
                "data":instruction.data_base58
            }]}]
        }));
        let report = inspect(&bytes, "devnet", "https://rpc.example", &fake).unwrap();
        assert_eq!(report.status, "RPC_SIMULATION_SUCCEEDED");
        assert_eq!(report.wire.asset_totals[0].declared_debit_raw, "1234");
        assert_eq!(report.endpoint_links[0].status, "ACCOUNT_MINT_ROW_MATCH");
        assert_eq!(
            report.endpoint_links[1].status,
            "INCOMPLETE_ACCOUNT_MINT_ROW"
        );
        assert_eq!(report.cpi_links.len(), 1);
        let value = serde_json::to_value(report).unwrap();
        let link = &value["cpi_links"][0];
        assert!(value.pointer(link["wire_ref"].as_str().unwrap()).is_some());
        assert_eq!(
            value
                .pointer(link["observation_ref"].as_str().unwrap())
                .unwrap()["amount_raw"],
            "1234"
        );
        assert!(!value["execution_proven"].as_bool().unwrap());
    }

    #[test]
    fn malformed_input_and_invalid_configuration_never_call_rpc() {
        let fake = provider(Value::Null);
        assert!(inspect(&[255], "devnet", "https://rpc.example", &fake).is_err());
        assert!(inspect(&fixture(), "bad", "https://rpc.example", &fake).is_err());
        assert!(inspect(&fixture(), "devnet", "http://rpc.example", &fake).is_err());
        assert_eq!(fake.calls.get(), 0);
    }
}
