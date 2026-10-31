use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::lexer::Span;
use super::read::Text;
use crate::ConfigDiagnostic;
use crate::assets::AssetsConfig;
use crate::diagnostic::Severity;
use crate::node::Node;
use crate::subscription::{DeclaringSource, Subscription};

pub(super) fn parse_node_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Node>, super::ParseFailure> {
    parse_node_section_indexed(section, diagnostics, |_, _| {})
}

pub(super) fn parse_node_section_indexed(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
    mut on_entry: impl FnMut(&Node, Span),
) -> Result<Vec<Node>, super::ParseFailure> {
    let mut nodes = Vec::new();
    let mut chains = Vec::new();
    let mut entry_index = 0;
    for root in section {
        let Some(body) = root.body_with(super::cursor::BodySyntax::Entries) else {
            continue;
        };
        for child in body {
            visit_node_segment(
                &child,
                diagnostics,
                &mut nodes,
                &mut chains,
                &mut entry_index,
                &mut on_entry,
            )?;
        }
    }
    link_chains(nodes, chains, diagnostics)
}

/// A `->` chain entry awaiting relay naming: its landing, its relays, a
/// trailing bare-name target (only for a named landing without relays), and
/// its diagnostic location.
struct PendingChain {
    landing: Landing,
    relays: Vec<Node>,
    target: Option<String>,
    entry: Option<usize>,
}

/// A chain landing: a node this entry declared, or (`my_node -> ...`) a node
/// declared by another entry of the section, by name.
enum Landing {
    Index(usize),
    Named(String),
}

/// Wire every `->` chain once all user-declared names are known, so
/// generated relay names never collide with a node declared later. Chains
/// declared on their own landing run first; named-landing declarations then
/// set (or must agree with) the named node's detour.
fn link_chains(
    nodes: Vec<Node>,
    mut chains: Vec<PendingChain>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Node>, super::ParseFailure> {
    if chains.is_empty() {
        return Ok(nodes);
    }
    chains.sort_by_key(|chain| matches!(chain.landing, Landing::Named(_)));
    let mut namer = crate::share_link::ChainNamer::new(&nodes);
    let mut landings: Vec<Option<Node>> = nodes.into_iter().map(Some).collect();
    let mut relays_out = Vec::new();
    for chain in chains {
        let (index, declared) = match &chain.landing {
            Landing::Index(index) => (*index, None),
            Landing::Named(name) => {
                let mut found = landings
                    .iter()
                    .enumerate()
                    .filter(|(_, node)| node.as_ref().is_some_and(|node| node.name == *name));
                match (found.next(), found.next()) {
                    (Some((index, _)), None) => (index, Some(name.clone())),
                    (first, _) => {
                        let message = if first.is_some() {
                            "node chain (->): the bare-name landing matches several nodes"
                        } else {
                            "node chain (->): the bare-name landing is not a node declared in \
                             this node section"
                        };
                        push_chain_warning(diagnostics, chain.entry, message);
                        continue;
                    }
                }
            }
        };
        let mut landing = landings[index].take().expect("landing present");
        let previous = if declared.is_some() {
            let previous = landing.detour.take();
            landing.id = landing.derive_id();
            previous
        } else {
            None
        };
        if chain.relays.is_empty() {
            landing.detour = chain.target.clone();
            landing.id = landing.derive_id();
        }
        let original = landing.clone();
        match namer.link(crate::share_link::ShareLinkChain {
            landing,
            relays: chain.relays,
        }) {
            Ok(mut linked) => {
                let landing = linked.remove(0);
                if let Some(previous) = previous
                    && landing.detour.as_ref() != Some(&previous)
                {
                    let mut error = crate::error::DetailedConfigError::new(
                        crate::error::ErrorCategory::Validation,
                        "conflicting-detour",
                        diagnostics.source(),
                        crate::diagnostic::SettingPath::new("nodes").field("chain"),
                        "node chain (->): conflicting detour declarations for the same node \
                         (identical repeats are fine)",
                    );
                    error.diagnostic.entry_index = chain.entry;
                    return Err(super::ParseFailure::Detailed(error));
                }
                relays_out.extend(linked);
                landings[index] = Some(landing);
            }
            Err(message) => {
                // Like any unusable entry: warn and drop it (never keep the
                // landing without its relays). A named landing stays as
                // declared by its own entry.
                if declared.is_some() {
                    let mut original = original;
                    original.detour = previous;
                    original.id = original.derive_id();
                    landings[index] = Some(original);
                }
                push_chain_warning(diagnostics, chain.entry, message);
            }
        }
    }
    let mut nodes: Vec<Node> = landings.into_iter().flatten().collect();
    nodes.extend(relays_out);
    Ok(nodes)
}

fn push_chain_warning(
    diagnostics: &mut ParserDiagnostics<'_>,
    entry: Option<usize>,
    message: &'static str,
) {
    let mut error = crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Validation,
        "invalid-chain",
        diagnostics.source(),
        crate::diagnostic::SettingPath::new("nodes").field("chain"),
        message,
    );
    error.diagnostic.entry_index = entry;
    error.diagnostic.severity = Severity::Warning;
    error.diagnostic.terminal = false;
    diagnostics.output.push(*error.diagnostic);
}

fn visit_node_segment<'d, 'a>(
    segment: &Segment<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
    nodes: &mut Vec<Node>,
    chains: &mut Vec<PendingChain>,
    entry_index: &mut usize,
    on_entry: &mut impl FnMut(&Node, Span),
) -> Result<(), super::ParseFailure> {
    diagnostics.at_section("node", Text::segment(segment));
    if let Some(header) = super::read::block_header(segment) {
        header.notice(
            diagnostics,
            Severity::Warning,
            "legacy-wrapper",
            "nested node wrapper is retained for compatibility",
        );
        if let Some(body) = segment.body_with(super::cursor::BodySyntax::Entries) {
            for child in body {
                visit_node_segment(&child, diagnostics, nodes, chains, entry_index, on_entry)?;
            }
        }
        return Ok(());
    }

    let text = Text::segment(segment).trim();
    if text.raw().is_empty() {
        return Ok(());
    }
    *entry_index += 1;
    diagnostics.entry_text(text, *entry_index);
    parse_node_entry(text, diagnostics, nodes, chains, *entry_index, on_entry)
}

fn parse_node_entry(
    text: Text<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
    nodes: &mut Vec<Node>,
    chains: &mut Vec<PendingChain>,
    entry_index: usize,
    on_entry: &mut impl FnMut(&Node, Span),
) -> Result<(), super::ParseFailure> {
    let raw = text.raw();
    if let Some(rest) = raw.strip_prefix("mux")
        && rest.trim_start().starts_with(['=', ':'])
    {
        let (line, column) = text.source.location(text.span.start);
        let mut error = crate::error::DetailedConfigError::new(
            crate::error::ErrorCategory::Parse,
            "unsupported-node-mux",
            text.source.reference(),
            crate::diagnostic::SettingPath::new("nodes").field("mux"),
            "standalone mux is unsupported; set mux on each VLESS share link",
        );
        error.diagnostic.line = Some(line);
        error.diagnostic.span = Some(text.span.start..text.span.end);
        error.diagnostic.byte_column = Some(column);
        return Err(super::ParseFailure::Detailed(error));
    }
    if text.has_error() {
        // The lexer has already emitted the one authoritative quote diagnostic.
        return Ok(());
    }

    let (tag, value) = split_entry(text, diagnostics);
    let (tag, uri) = if let Some(tag) = tag {
        if !tag
            .quoted_prefix()
            .is_some_and(|quote| quote.span == tag.span)
            && tag.raw().chars().any(char::is_whitespace)
        {
            (None, text)
        } else {
            (Some(tag.unquote()), value)
        }
    } else {
        (None, value)
    };

    let Some((uri, end)) = complete_quoted_value(uri, diagnostics) else {
        return Ok(());
    };
    let hops = crate::share_link::chain_hops(uri.raw());
    if hops.len() > 1 && crate::share_link::is_bare_name(hops[0]) {
        return parse_detour_declaration(
            text,
            tag.map(|tag| tag.raw().to_owned()),
            &hops,
            diagnostics,
            chains,
            entry_index,
        );
    }
    match diagnostics.parse_share_link(uri.raw()) {
        Ok(chain) => {
            let mut node = chain.landing;
            if let Some(tag) = tag.filter(|tag| !tag.raw().is_empty()) {
                node.name = tag.raw().to_owned();
            }
            on_entry(&node, text.source.span(text.span.start, end));
            if !chain.relays.is_empty() {
                chains.push(PendingChain {
                    landing: Landing::Index(nodes.len()),
                    relays: chain.relays,
                    target: None,
                    entry: Some(entry_index),
                });
            }
            nodes.push(node);
        }
        Err(error) if error.category == crate::error::ErrorCategory::UnknownProtocol => {
            return Err(super::ParseFailure::Detailed(error));
        }
        Err(error) if error.diagnostic.code == "removed-vless-mode" => {
            return Err(super::ParseFailure::Detailed(error));
        }
        Err(mut error)
            if !matches!(error.diagnostic.code, "config-parse" | "config-validation") =>
        {
            error.diagnostic.severity = Severity::Warning;
            error.diagnostic.terminal = false;
            diagnostics.output.push(*error.diagnostic);
        }
        Err(_) => {
            text.notice(
                diagnostics,
                Severity::Warning,
                "invalid-node-entry",
                "node entry could not be parsed; ignored",
            );
        }
    }
    Ok(())
}

/// `'my_node -> relay...'`: a chain whose landing is a node already declared
/// in this section by name. It adds no node; it declares the named node's
/// detour (resolved after every entry is read).
fn parse_detour_declaration(
    text: Text<'_, '_>,
    tag: Option<String>,
    hops: &[&str],
    diagnostics: &mut ParserDiagnostics<'_>,
    chains: &mut Vec<PendingChain>,
    entry_index: usize,
) -> Result<(), super::ParseFailure> {
    let name = hops[0].to_owned();
    if tag
        .as_ref()
        .is_some_and(|tag| !tag.is_empty() && *tag != name)
    {
        text.notice(
            diagnostics,
            Severity::Warning,
            "invalid-chain",
            "a bare-name chain landing declares that node's detour; its entry tag must be \
             empty or equal the landing name; entry ignored",
        );
        return Ok(());
    }
    let (relays, target) = if hops.len() == 2 && crate::share_link::is_bare_name(hops[1]) {
        (Vec::new(), Some(hops[1].to_owned()))
    } else {
        let rest = hops[1..].join(" -> ");
        if crate::share_link::is_bare_name(hops[1]) {
            text.notice(
                diagnostics,
                Severity::Warning,
                "invalid-chain",
                "node chain (->): a bare node/group name hop must be the last (rightmost) hop; \
                 entry ignored",
            );
            return Ok(());
        }
        match diagnostics.parse_share_link(&rest) {
            Ok(chain) => {
                let mut relays = vec![chain.landing];
                relays.extend(chain.relays);
                (relays, None)
            }
            Err(mut error) => {
                error.diagnostic.severity = Severity::Warning;
                error.diagnostic.terminal = false;
                diagnostics.output.push(*error.diagnostic);
                return Ok(());
            }
        }
    };
    chains.push(PendingChain {
        landing: Landing::Named(name),
        relays,
        target,
        entry: Some(entry_index),
    });
    Ok(())
}

fn complete_quoted_value<'d, 'a>(
    value: Text<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Option<(Text<'d, 'a>, usize)> {
    let value = value.trim();
    let Some(quote) = value.quoted_prefix() else {
        return Some((value, value.span.end));
    };
    if quote.span == value.span {
        return Some((quote.unquote(), quote.span.end));
    }
    let tail = value.sub(quote.raw().len(), value.raw().len()).trim();
    if warn_glued_comment(tail, diagnostics) {
        return Some((quote.unquote(), quote.span.end));
    }
    if !tail.raw().is_empty() {
        tail.notice(
            diagnostics,
            Severity::Warning,
            "trailing-entry-text",
            "text after a quoted entry link; entry is skipped",
        );
    }
    None
}

fn warn_glued_comment(tail: Text<'_, '_>, diagnostics: &mut ParserDiagnostics<'_>) -> bool {
    let tail = tail.trim();
    if !tail.raw().starts_with('#') {
        return false;
    }
    tail.sub(0, 1).notice(
        diagnostics,
        Severity::Warning,
        "legacy-glued-hash",
        "put whitespace before a comment",
    );
    true
}

pub(super) fn parse_subscription_section(
    section: &[Segment<'_, '_>],
    assets: &AssetsConfig,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Subscription>, super::ParseFailure> {
    parse_subscription_section_indexed(section, assets, diagnostics, |_, _| {})
}

/// A legacy wrapper header may itself emit a subscription while owning other
/// entries. Its absent span forbids deleting that header along with its children.
pub(super) fn parse_subscription_section_indexed(
    section: &[Segment<'_, '_>],
    assets: &AssetsConfig,
    diagnostics: &mut ParserDiagnostics<'_>,
    mut on_entry: impl FnMut(&Subscription, Option<Span>),
) -> Result<Vec<Subscription>, super::ParseFailure> {
    let mut subscriptions = Vec::new();
    let mut entry_index = 0;
    for root in section {
        let Some(body) = root.body_with(super::cursor::BodySyntax::Entries) else {
            continue;
        };
        for child in body {
            visit_subscription_segment(
                &child,
                assets,
                diagnostics,
                &mut subscriptions,
                &mut entry_index,
                &mut on_entry,
            )?;
        }
    }
    Ok(subscriptions)
}

fn visit_subscription_segment<'d, 'a>(
    segment: &Segment<'d, 'a>,
    assets: &AssetsConfig,
    diagnostics: &mut ParserDiagnostics<'_>,
    subscriptions: &mut Vec<Subscription>,
    entry_index: &mut usize,
    on_entry: &mut impl FnMut(&Subscription, Option<Span>),
) -> Result<(), super::ParseFailure> {
    diagnostics.at_section("subscription", Text::segment(segment));
    let block = block_tag(segment)
        .map(|tag| (tag, None))
        .or_else(|| entry_block_header(segment).map(|(tag, url)| (tag, Some(url))));
    if let Some((tag, url)) = block {
        *entry_index += 1;
        diagnostics.subscription_text(Text::segment(segment).trim(), *entry_index);
        let subscription =
            parse_subscription_block(segment, tag, url, *entry_index, assets, diagnostics)?;
        on_entry(&subscription, Some(segment.span()));
        subscriptions.push(subscription);
        return Ok(());
    }

    if let Some(header) = super::read::block_header(segment) {
        header.notice(
            diagnostics,
            Severity::Warning,
            "legacy-wrapper",
            "nested subscription wrapper is retained for compatibility",
        );
        let mut entry = Text::segment(segment);
        if let Some(opener) = segment.opening_span() {
            entry.span.end = opener.start + 1;
        }
        *entry_index += 1;
        diagnostics.entry_text(entry, *entry_index);
        if let Some((subscription, _)) = parse_subscription_entry(entry, assets, diagnostics) {
            on_entry(&subscription, None);
            subscriptions.push(subscription);
        }
        if let Some(body) = segment.body_with(super::cursor::BodySyntax::Entries) {
            for child in body {
                visit_subscription_segment(
                    &child,
                    assets,
                    diagnostics,
                    subscriptions,
                    entry_index,
                    on_entry,
                )?;
            }
        }
        return Ok(());
    }

    let text = Text::segment(segment).trim();
    if text.raw().is_empty() {
        return Ok(());
    }
    *entry_index += 1;
    diagnostics.entry_text(text, *entry_index);
    if let Some((subscription, span)) = parse_subscription_entry(text, assets, diagnostics) {
        on_entry(&subscription, Some(span));
        subscriptions.push(subscription);
    }
    Ok(())
}

fn block_tag<'d, 'a>(segment: &Segment<'d, 'a>) -> Option<Text<'d, 'a>> {
    let header = super::read::block_header(segment)?;
    let (tag, value) = header.kv()?;
    value.raw().is_empty().then_some(tag)
}

/// `tag: 'url' { … }`: a whole-quoted link followed by the entry's own options.
/// Any other header before a block stays a legacy wrapper.
fn entry_block_header<'d, 'a>(segment: &Segment<'d, 'a>) -> Option<(Text<'d, 'a>, Text<'d, 'a>)> {
    let header = super::read::block_header(segment)?;
    if header.has_error() {
        return None;
    }
    let (tag, value) = header.kv()?;
    let value = value.trim();
    let quote = value
        .quoted_prefix()
        .filter(|quote| quote.span == value.span)?;
    Some((tag, quote.unquote()))
}

#[derive(Default)]
struct SubscriptionFields<'d, 'a> {
    url: Option<Text<'d, 'a>>,
    user_agent: Option<Text<'d, 'a>>,
    interval: Option<Text<'d, 'a>>,
    cache: Option<Text<'d, 'a>>,
    route: Option<Text<'d, 'a>>,
    download_detour: Option<Text<'d, 'a>>,
}

/// The old `tag: { url: … }` block also reads `url` and `download_detour`;
/// the entry form keeps its link on the header and takes only options.
fn collect_subscription_fields<'d, 'a>(
    segment: &Segment<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
    fields: &mut SubscriptionFields<'d, 'a>,
    legacy: bool,
) {
    let Some(body) = segment.body() else {
        return;
    };
    for child in body {
        let mut text = Text::segment(&child);
        if let Some(opener) = child.opening_span() {
            text.span.end = opener.end;
        }
        let text = text.trim();
        if !legacy
            && entry_block_header(&child).is_some()
            && let Some((key, _)) = text.kv()
        {
            key.notice(
                diagnostics,
                Severity::Warning,
                "unknown-key",
                "nested subscription entry ignored",
            );
            continue;
        }
        if let Some((key, value)) = text.kv() {
            diagnostics.register_field(key.raw(), value);
            let value = value.unquote();
            match key.raw() {
                "url" if legacy => fields.url = Some(value),
                "ua" => fields.user_agent = Some(value),
                "interval" => fields.interval = Some(value),
                "cache" => fields.cache = Some(value),
                "route" => fields.route = Some(value),
                "download_detour" if legacy => fields.download_detour = Some(value),
                _ if super::read::block_header(&child).is_none() => key.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-key",
                    "unknown scalar key ignored",
                ),
                _ => {}
            }
        }
        if super::read::block_header(&child).is_some() {
            Text::segment(&child).notice(
                diagnostics,
                Severity::Warning,
                "legacy-wrapper",
                "nested subscription wrapper is retained for compatibility",
            );
            collect_subscription_fields(&child, diagnostics, fields, legacy);
        }
    }
}

/// `url` is the entry form's header link; `None` reads the old block form.
fn parse_subscription_block<'d, 'a>(
    segment: &Segment<'d, 'a>,
    tag: Text<'d, 'a>,
    url: Option<Text<'d, 'a>>,
    index: usize,
    assets: &AssetsConfig,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Subscription, super::ParseFailure> {
    let mut subscription = Subscription {
        name: canonical_tag(tag),
        source: Some(DeclaringSource(Text::segment(segment).source.reference())),
        ..assets.subscription_base()
    };
    let mut fields = SubscriptionFields {
        url,
        ..Default::default()
    };
    collect_subscription_fields(segment, diagnostics, &mut fields, url.is_none());
    if let (Some(route), Some(_)) = (fields.route, fields.download_detour) {
        let (line, column) = route.source.location(route.span.start);
        let mut error = crate::error::DetailedConfigError::new(
            crate::error::ErrorCategory::Parse,
            "conflicting-subscription-route",
            route.source.reference(),
            crate::diagnostic::SettingPath::new("subscriptions")
                .index(index)
                .field("route"),
            "subscription entry sets both route and download_detour",
        );
        error.diagnostic.value =
            crate::diagnostic::SafeValue::Fields(vec!["route", "download_detour"]);
        error.diagnostic.line = Some(line);
        error.diagnostic.span = Some(route.span.start..route.span.end);
        error.diagnostic.byte_column = Some(column);
        return Err(super::ParseFailure::Detailed(error));
    }
    if let Some(url) = fields.url {
        subscription.url = url.raw().to_owned();
    }
    if let Some(user_agent) = fields.user_agent {
        subscription.user_agent = Some(user_agent.raw().to_owned());
    }
    if let Some(detour) = fields.route.or(fields.download_detour) {
        subscription.download_detour = detour.raw().to_owned();
    }
    if let Some(interval) = fields.interval {
        let value = interval.raw();
        subscription.update_interval = super::lenient(
            crate::types::parse_duration_secs(value),
            0,
            diagnostics,
            || ConfigDiagnostic {
                setting: format!("subscription.{}.interval", subscription.name),
                value: value.to_owned(),
                message: "duration is unsupported by honk; using fallback 0s".to_string(),
            },
        );
    }
    if let Some(cache) = fields.cache {
        let value = cache.raw();
        subscription.cache = super::lenient(
            super::scalars::strict_bool(value),
            true,
            diagnostics,
            || ConfigDiagnostic {
                setting: format!("subscription.{}.cache", subscription.name),
                value: value.to_owned(),
                message: "value is not a boolean; using fallback true".to_string(),
            },
        );
    }
    Ok(subscription)
}

fn parse_subscription_entry(
    text: Text<'_, '_>,
    assets: &AssetsConfig,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Option<(Subscription, Span)> {
    if text.has_error() {
        // Keep the lexer diagnostic; do not add a second malformed-entry warning.
        return None;
    }
    let (tag, value) = split_entry(text, diagnostics);
    let (value, user_agent, end) = parse_subscription_value(value, diagnostics)?;
    let (tag, value) = if tag.is_none() {
        embedded_tag(value, diagnostics).unwrap_or((None, value))
    } else {
        (tag, value)
    };
    let url = value.unquote().raw().to_owned();
    let name = if let Some(tag) = tag {
        canonical_tag(tag)
    } else {
        if !url.contains("://") {
            return None;
        }
        url::Url::parse(&url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let base = assets.subscription_base();
    Some((
        Subscription {
            name,
            url,
            user_agent: user_agent.or(base.user_agent.clone()),
            source: Some(DeclaringSource(text.source.reference())),
            ..base
        },
        text.source.span(text.span.start, end),
    ))
}

fn embedded_tag<'d, 'a>(
    value: Text<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Option<(Option<Text<'d, 'a>>, Text<'d, 'a>)> {
    let value = value.trim();
    let quote = value
        .quoted_prefix()
        .filter(|quote| quote.span == value.span)?;
    let inner = quote.unquote();
    let colon = inner.raw().find(':')?;
    if inner.raw()[colon..].starts_with("://") || !inner.raw()[colon + 1..].contains("://") {
        return None;
    }
    value.notice(
        diagnostics,
        Severity::Warning,
        "legacy-embedded-tag",
        "whole-quoted subscription tags are retained for compatibility",
    );
    Some((
        Some(inner.sub(0, colon).trim()),
        inner.sub(colon + 1, inner.raw().len()).trim(),
    ))
}

fn parse_subscription_value<'d, 'a>(
    value: Text<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Option<(Text<'d, 'a>, Option<String>, usize)> {
    let value = value.trim();
    let Some(quote) = value.quoted_prefix() else {
        return Some((value, None, value.span.end));
    };
    if quote.span == value.span {
        return Some((quote, None, quote.span.end));
    }
    let remainder = value.sub(quote.raw().len(), value.raw().len()).trim();
    if warn_glued_comment(remainder, diagnostics) {
        return Some((quote, None, quote.span.end));
    }
    if !remainder.raw().starts_with('(') {
        remainder.trim().notice(
            diagnostics,
            Severity::Warning,
            "trailing-entry-text",
            "text after a quoted subscription link; entry is skipped",
        );
        return None;
    }
    let Some((ua_text, tail)) = remainder.parenthesized() else {
        remainder.notice(
            diagnostics,
            Severity::Warning,
            "trailing-entry-text",
            "incomplete user-agent suffix; entry is skipped",
        );
        return None;
    };
    if !tail.raw().trim().is_empty() && !warn_glued_comment(tail, diagnostics) {
        let offset = tail.raw().len() - tail.raw().trim_start().len();
        tail.sub(
            offset,
            offset + tail.raw()[offset..].chars().next().unwrap().len_utf8(),
        )
        .notice(
            diagnostics,
            Severity::Error,
            "legacy-ua-boundary",
            "text glued after a user-agent suffix; entry is skipped",
        );
        return None;
    }
    Some((quote, Some(canonical_ua(ua_text)), tail.span.start))
}

fn canonical_ua(value: Text<'_, '_>) -> String {
    let trimmed = value.trim();
    if trimmed
        .quoted_prefix()
        .is_some_and(|quote| quote.span == trimmed.span)
    {
        trimmed.unquote().raw().to_owned()
    } else {
        value.raw().to_owned()
    }
}

fn canonical_tag(value: Text<'_, '_>) -> String {
    value.trim().unquote().raw().to_owned()
}

fn split_entry<'d, 'a>(
    text: Text<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> (Option<Text<'d, 'a>>, Text<'d, 'a>) {
    let text = text.trim();
    let colon = if let Some(quote) = text.quoted_prefix() {
        let remainder = text.sub(quote.raw().len(), text.raw().len()).trim();
        if !remainder.raw().starts_with(':') {
            return (None, text);
        }
        remainder.span.start - text.span.start
    } else if let Some(colon) = text.find(":") {
        if text.raw()[colon..].starts_with("://") {
            return (None, text);
        }
        colon
    } else {
        return (None, text);
    };
    let raw_tag = text.sub(0, colon);
    let tag = raw_tag.trim();
    let value = text.sub(colon + 1, text.raw().len()).trim();
    if !tag
        .quoted_prefix()
        .is_some_and(|quote| quote.span == tag.span)
        && raw_tag.span != tag.span
    {
        raw_tag.notice(
            diagnostics,
            Severity::Info,
            "entry-tag-normalized",
            "whitespace around an entry tag colon was normalized",
        );
    }
    (Some(tag), value)
}
