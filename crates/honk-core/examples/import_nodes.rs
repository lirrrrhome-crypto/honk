//! Run a subscription body through the real importer and print the nodes as
//! JSON (the structured node form `chain_probe` accepts as `<nodes.json>`).
//!
//! Usage: import_nodes <clash|auto> <file>
//! `clash` parses Clash/mihomo YAML; `auto` detects sing-box JSON, SIP008,
//! base64 or plain share links like a `Simple` subscription.
use honk_config::subscription::Subscription;
use honk_config::types::SubscriptionType;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: import_nodes <clash|auto> <file>");
    let sub_type = match args[1].as_str() {
        "clash" => SubscriptionType::Clash,
        "auto" => SubscriptionType::Simple,
        other => anyhow::bail!("unknown format {other}"),
    };
    let content = std::fs::read_to_string(&args[2])?;
    let nodes = honk_core::subscription::parse_subscription_content(
        &Subscription {
            sub_type,
            ..Default::default()
        },
        &content,
    )?;
    println!("{}", serde_json::to_string_pretty(&nodes)?);
    Ok(())
}
