from .features import parse_url, extract_features
from .model import predict

def add(findings, points, category, message):
    findings.append({"category": category, "points": points, "finding": message})

def score(findings):
    return min(sum(item["points"] for item in findings), 1.0)

def static_analysis(features):
    findings = []
    if features["uses_https"] == 0:
        add(findings, .12, "Transport", "The URL does not use HTTPS.")
    if features["dangerous_scheme"]:
        add(findings, .60, "Protocol", "The URL uses a dangerous script, data, or local-file scheme.")
    if features["unusual_scheme"]:
        add(findings, .25, "Protocol", "The URL uses an unusual protocol scheme.")
    if features["has_ip_hostname"]:
        add(findings, .25, "Host", "The hostname is an IP address instead of a normal domain.")
    if features["localhost_reference"]:
        add(findings, .25, "Host", "The URL references localhost or a local address.")
    if features["at_count"] > 0:
        add(findings, .18, "Obfuscation", "The URL contains '@', which can hide the real destination.")
    if features["url_length"] > 120:
        add(findings, .10, "Structure", "The URL is unusually long.")
    if features["suspicious_tld"]:
        add(findings, .16, "Domain", "The URL uses a high-risk or commonly abused TLD.")
    if features["domain_length"] <= 10 and features["domain_entropy"] >= 2.7 and features["suspicious_tld"]:
        add(findings, .18, "Domain", "The domain name is short, unfamiliar-looking, and uses a risky TLD.")
    if features["subdomain_depth"] >= 3:
        add(findings, .12, "Structure", "The URL has many subdomains.")
    if features["first_label_length"] >= 18 and features["first_label_entropy"] >= 3.3:
        add(findings, .22, "Domain", "The first subdomain looks randomly generated.")
    if features["random_like_token_count"] >= 1:
        add(findings, .14, "Obfuscation", "The URL contains long random-looking tokens.")
    if features["keyword_count"] >= 2:
        add(findings, .14, "Language", "Multiple sensitive or scam-related words were found.")
    elif features["keyword_count"] == 1:
        add(findings, .06, "Language", "A sensitive or scam-related word was found.")
    if features["keyword_in_domain"]:
        add(findings, .08, "Domain", "The registered domain contains suspicious wording.")
    if features["brand_count"] > 0 and not features["domain_contains_brand"]:
        add(findings, .12, "Impersonation", "A known brand appears outside the registered domain.")
    if features["is_shortener"]:
        add(findings, .10, "Obfuscation", "The URL uses a shortener.")
    if features["is_tracking_domain"]:
        add(findings, .18, "Tracking", "The link uses a marketing or campaign tracking domain.")
    if features["tracking_param_count"] >= 3:
        add(findings, .22, "Tracking", "The URL contains multiple tracking or campaign parameters.")
    if features["affiliate_param_count"] >= 3:
        add(findings, .24, "Affiliate Fraud", "The URL contains multiple affiliate or traffic-source parameters.")
    if features["repeated_param_count"] >= 1:
        add(findings, .08, "Manipulation", "The URL repeats parameter names.")
    if features["numeric_param_count"] >= 3:
        add(findings, .12, "Tracking", "The URL contains many numeric campaign identifiers.")
    if features["empty_param_count"] >= 2:
        add(findings, .07, "Structure", "The URL contains multiple empty tracking parameters.")
    if features["hash_value_count"] >= 1:
        add(findings, .12, "Tracking", "The URL contains a long hash-like tracking value.")
    if features["ip_value_count"] >= 1:
        add(findings, .18, "Privacy", "The URL contains an IP address as a parameter.")
    if features["domain_param_mismatch"]:
        add(findings, .22, "Redirect", "The URL contains a domain parameter that does not match the actual hostname.")
    if features["click_action_fragment"]:
        add(findings, .24, "Tracking", "The fragment contains click-tracking action parameters.")
    if features["fragment_has_query_style"]:
        add(findings, .14, "Obfuscation", "The URL hides query-style parameters inside the fragment.")
    if features["short_token_path"]:
        add(findings, .16, "Tracking", "The path contains a short redirect or campaign token.")
    if features["hyphen_count"] >= 3:
        add(findings, .06, "Structure", "The URL contains many hyphens.")
    if features["digit_ratio"] > .20:
        add(findings, .07, "Structure", "The URL contains an unusually high amount of digits.")
    if features["hostname_entropy"] > 4.0:
        add(findings, .08, "Domain", "The hostname looks highly random.")
    if features["percent_count"] > 2:
        add(findings, .06, "Obfuscation", "The URL contains heavy encoding.")
    if features["risky_extension"]:
        add(findings, .18, "Payload", "The URL points to a risky executable, script, macro, or archive file type.")
    if features["long_query"]:
        add(findings, .05, "Structure", "The URL contains a long query string.")
    if features["long_fragment"]:
        add(findings, .08, "Obfuscation", "The URL contains a long fragment section.")
    if features["is_tracking_domain"] and features["first_label_length"] >= 18 and features["tracking_param_count"] >= 3:
        add(findings, .45, "Strict Rule", "Strict rule matched: tracking domain, random subdomain, and campaign identifiers.")
    if features["click_action_fragment"] and features["numeric_param_count"] >= 4 and features["short_token_path"]:
        add(findings, .40, "Strict Rule", "Strict rule matched: click action, numeric campaign identifiers, and redirect-token path.")
    if features["affiliate_param_count"] >= 4 and features["domain_param_mismatch"] and features["ip_value_count"]:
        add(findings, .48, "Strict Rule", "Strict rule matched: affiliate parameters, mismatched destination domain, and IP tracking.")
    if features["suspicious_tld"] and features["affiliate_param_count"] >= 3 and features["hash_value_count"]:
        add(findings, .38, "Strict Rule", "Strict rule matched: risky TLD, affiliate parameters, and hash-like tracking value.")
    return score(findings), findings

def level(value):
    if value >= .80:
        return "Critical"
    if value >= .60:
        return "High"
    if value >= .35:
        return "Medium"
    return "Low"

def recommendation(risk_level, trusted=False):
    if trusted and risk_level == "Low":
        return "This looks like a normal link on a trusted, well-known domain. Still avoid entering data if the message was unexpected."
    return {
        "Critical": "Do not open this link or enter any information. Report it immediately.",
        "High": "Avoid this link unless the sender and destination are independently verified.",
        "Medium": "Proceed carefully and manually verify the domain before entering information.",
        "Low": "No major scam indicators were found. Stay cautious with unexpected links."
    }[risk_level]

def trusted_confidence(features, current_score, findings):
    if not features["trusted_registered_domain"]:
        return current_score, findings, False
    dangerous = any([
        features["dangerous_scheme"], features["has_ip_hostname"], features["domain_param_mismatch"],
        features["ip_value_count"], features["risky_extension"], features["suspicious_tld"],
        features["is_tracking_domain"], features["affiliate_param_count"] >= 3,
        features["tracking_param_count"] >= 5, features["random_like_token_count"] >= 2
    ])
    if dangerous:
        return current_score, findings, False
    if features["uses_https"] and features["direct_trusted_host"] and features["safe_path"] and features["param_count"] <= 3:
        findings.append({"category": "Trusted Domain", "points": 0.0, "finding": "The link is on a known trusted domain with a normal structure."})
        return min(current_score, .18), findings, True
    if features["uses_https"] and features["trusted_registered_domain"] and features["param_count"] <= 5:
        findings.append({"category": "Trusted Domain", "points": 0.0, "finding": "The link is on a known trusted registered domain."})
        return min(current_score, .28), findings, True
    return current_score, findings, False

def strict_override(features, current_score, findings):
    floor = 0.0
    if features["is_tracking_domain"] and features["first_label_length"] >= 18 and features["tracking_param_count"] >= 3:
        floor = max(floor, .82)
        findings.append({"category": "Risk Override", "points": 0.0, "finding": "Risk override: tracking domain with random subdomain and campaign identifiers."})
    if features["click_action_fragment"] and features["numeric_param_count"] >= 4 and features["short_token_path"]:
        floor = max(floor, .84)
        findings.append({"category": "Risk Override", "points": 0.0, "finding": "Risk override: click-tracking fragment, numeric campaign IDs, and redirect-token path."})
    if features["affiliate_param_count"] >= 4 and features["domain_param_mismatch"] and features["ip_value_count"]:
        floor = max(floor, .86)
        findings.append({"category": "Risk Override", "points": 0.0, "finding": "Risk override: affiliate parameters, mismatched domain, and IP tracking."})
    if features["suspicious_tld"] and features["affiliate_param_count"] >= 3 and features["hash_value_count"]:
        floor = max(floor, .78)
        findings.append({"category": "Risk Override", "points": 0.0, "finding": "Risk override: risky TLD with affiliate tracking and hash identifier."})
    if features["dangerous_scheme"]:
        floor = max(floor, .95)
        findings.append({"category": "Risk Override", "points": 0.0, "finding": "Risk override: dangerous URL scheme."})
    if floor > current_score:
        current_score = floor
    return current_score, findings

def analyze_url(url, model=None, online=True, user_reported=False):
    parsed, normalized = parse_url(url)
    features = extract_features(normalized)
    static_score, findings = static_analysis(features)
    prediction, ml_probability = predict(normalized, model=model)

    if ml_probability is None:
        final_score = static_score
        model_used = False
    else:
        final_score = max(static_score, .25 * ml_probability + .75 * static_score)
        model_used = True

    final_score, findings = strict_override(features, final_score, findings)

    if user_reported:
        final_score = max(final_score, .75)
        findings.append({"category": "User Report", "points": 0.0, "finding": "The user marked this link as suspicious, scam, or fraudulent."})

    final_score, findings, trusted = trusted_confidence(features, final_score, findings)

    final_score = min(final_score, 1.0)
    risk_level = level(final_score)
    if not findings:
        findings = [{"category": "General", "points": 0.0, "finding": "No strong scam indicators were detected."}]

    return {
        "product": "LinkShield",
        "input_url": url,
        "normalized_url": normalized,
        "risk_level": risk_level,
        "risk_score": round(final_score, 4),
        "risk_percent": round(final_score * 100, 2),
        "recommendation": recommendation(risk_level, trusted=trusted),
        "trusted_domain_confidence": trusted,
        "model_used": model_used,
        "model_prediction": prediction,
        "model_probability": None if ml_probability is None else round(ml_probability, 4),
        "static_score": round(static_score, 4),
        "online_checks": online,
        "user_reported": user_reported,
        "findings": findings,
        "features": features
    }
