import math
import re
import ipaddress
from urllib.parse import urlparse, unquote, parse_qsl
import tldextract

SAFE_DOMAINS = {
    "google.com","youtube.com","gmail.com","microsoft.com","office.com","live.com","outlook.com",
    "apple.com","icloud.com","amazon.com","paypal.com","netflix.com","github.com","stackoverflow.com",
    "wikipedia.org","mozilla.org","cloudflare.com","openai.com","python.org","ubuntu.com","debian.org",
    "bbc.com","reuters.com","nytimes.com","linkedin.com","discord.com","steampowered.com",
    "dropbox.com","adobe.com","spotify.com","paypal.de","sparkasse.de","postbank.de",
    "vodafone.de","telekom.de","o2online.de","gov.uk","europa.eu"
}

SUSPICIOUS_WORDS = [
    "login","verify","secure","account","update","confirm","password","signin","payment",
    "billing","unlock","suspended","recover","alert","validate","wallet","bank","limited",
    "urgent","blocked","restore","identity","kyc","2fa","mfa","otp","token","invoice",
    "gift","bonus","free","claim","prize","support","security","authentication","click",
    "reward","winner","access","expire","expired","locked","action","loan","crypto",
    "airdrop","profit","investment","casino","spin","win","voucher"
]

BRANDS = [
    "paypal","google","microsoft","apple","amazon","facebook","meta","instagram","netflix",
    "binance","coinbase","steam","discord","whatsapp","telegram","sparkasse","postbank",
    "chase","visa","mastercard","dhl","ups","fedex","icloud","office365","dropbox",
    "vodafone","telekom","o2","vodacom"
]

SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly",
    "rebrand.ly","shorturl.at","s.id","lnkd.in","rb.gy","shorte.st"
]

TRACKING_DOMAINS = [
    "activedemand.com","hubspotlinks.com","list-manage.com","sendgrid.net","mailchi.mp",
    "constantcontact.com","marketo.com","pardot.com","salesforce.com","mailgun.org",
    "sendinblue.com","brevo.com","klclick.com","clickdimensions.com","clickfunnels.com",
    "trackingdomain.com"
]

TRACKING_PARAMS = [
    "utm_source","utm_medium","utm_campaign","utm_content","utm_term","uid","vid","cid",
    "pid","lid","ofid","act","redirect","url","target","u","r","click","clickid","trk",
    "mc_cid","mc_eid","mkt_tok","fbclid","gclid","msclkid","source","source_id",
    "affiliate","aff","affid","subid","sub_id","sub1","sub2","sub3","sub4","sub5",
    "campaign","campaign_id","ad","adid","ad_id","creative","placement","click_id",
    "encoded_value","domain","ip","zoneid","offer","offer_id","transaction_id"
]

AFFILIATE_PARAMS = [
    "sub1","sub2","sub3","sub4","sub5","source_id","encoded_value","domain","ip",
    "aff","affid","affiliate","offer","offer_id","zoneid","campaign_id","click_id"
]

RISKY_EXTENSIONS = [
    "exe","scr","bat","cmd","js","vbs","jar","msi","apk","zip","rar","7z","iso",
    "dmg","ps1","hta","lnk","docm","xlsm","pptm"
]

SUSPICIOUS_TLDS = [
    "lat","zip","mov","top","xyz","click","country","stream","gq","tk","ml","cf","ga",
    "work","quest","monster","cam","icu","rest","buzz","fit","kim","cyou","sbs","bar",
    "live","loan","men","date","racing","download","party","review","trade","science",
    "cfd","bond","beauty","mom","pics","autos","homes","skin","hair"
]

def entropy(value):
    if not value:
        return 0.0
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    result = 0.0
    for count in freq.values():
        p = count / len(value)
        result -= p * math.log2(p)
    return result

def vowel_ratio(value):
    letters = [c for c in value.lower() if c.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for c in letters if c in "aeiou")
    return vowels / len(letters)

def consonant_run(value):
    longest = 0
    current = 0
    for c in value.lower():
        if c.isalpha() and c not in "aeiou":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest

def normalize_url(url):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url

def parse_url(url):
    normalized = normalize_url(url)
    return urlparse(normalized), normalized

def domain_parts(hostname):
    ext = tldextract.extract(hostname or "")
    registered = ".".join(part for part in [ext.domain, ext.suffix] if part)
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": registered
    }

def is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return 1
    except Exception:
        return 0

def is_ip_literal(value):
    value = unquote(str(value)).strip("[]")
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def looks_hex_hash(value):
    value = str(value)
    return bool(re.fullmatch(r"[a-fA-F0-9]{24,}", value))

def is_empty(value):
    return value is None or str(value) == ""

def extract_features(url):
    parsed, normalized = parse_url(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    fragment_clean = fragment[1:] if fragment.startswith("?") else fragment
    decoded = unquote(normalized)
    lower = decoded.lower()
    parts = domain_parts(hostname)
    registered = parts["registered_domain"]
    suffix = parts["suffix"]
    subdomain = parts["subdomain"]
    labels = [x for x in hostname.split(".") if x]
    first_label = labels[0] if labels else ""
    query_pairs = parse_qsl(query, keep_blank_values=True)
    fragment_pairs = parse_qsl(fragment_clean, keep_blank_values=True)
    all_pairs = query_pairs + fragment_pairs
    all_params = [k.lower() for k, v in all_pairs]
    values = [v for k, v in all_pairs]
    ext_match = re.search(r"\.([a-zA-Z0-9]{1,8})(?:$|\?)", path.lower())
    extension = ext_match.group(1) if ext_match else ""
    digits = sum(c.isdigit() for c in normalized)
    letters = sum(c.isalpha() for c in normalized)
    special = sum(not c.isalnum() for c in normalized)
    long_alnum_tokens = re.findall(r"[a-zA-Z0-9]{12,}", normalized)
    random_like_tokens = [t for t in long_alnum_tokens if entropy(t) >= 3.2 and vowel_ratio(t) < 0.42]
    tracking_param_count = sum(1 for p in all_params if p in TRACKING_PARAMS)
    affiliate_param_count = sum(1 for p in all_params if p in AFFILIATE_PARAMS)
    repeated_param_count = len(all_params) - len(set(all_params))
    numeric_param_count = sum(1 for k, v in all_pairs if str(v).isdigit() and len(str(v)) >= 2)
    empty_param_count = sum(1 for k, v in all_pairs if is_empty(v))
    hash_value_count = sum(1 for v in values if looks_hex_hash(v))
    ip_value_count = sum(1 for v in values if is_ip_literal(v))
    domain_param_mismatch = 0
    for k, v in all_pairs:
        if k.lower() == "domain":
            clean = str(v).lower().strip()
            clean = clean.replace("https://", "").replace("http://", "").strip("/")
            if clean and clean not in hostname.lower():
                domain_param_mismatch = 1
    short_token_path = int(bool(re.fullmatch(r"/s/[A-Za-z0-9_-]{8,}", path)))
    click_action_fragment = int(any(p in ["act", "pid", "uid", "vid", "ofid", "lid", "cid"] for p in all_params))
    tracking_domain = int(registered in TRACKING_DOMAINS or any(registered.endswith("." + d) for d in TRACKING_DOMAINS))
    suspicious_tld = int(suffix in SUSPICIOUS_TLDS)
    trusted_registered_domain = int(registered in SAFE_DOMAINS)
    direct_trusted_host = int((hostname == registered or hostname == "www." + registered) and registered in SAFE_DOMAINS)
    safe_path = int(path in ["", "/"] or path.startswith(("/about","/support","/help","/docs","/blog","/news","/login","/signin","/account","/resources","/pricing")))

    return {
        "url_length": len(normalized),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "dot_count": normalized.count("."),
        "hyphen_count": normalized.count("-"),
        "underscore_count": normalized.count("_"),
        "slash_count": normalized.count("/"),
        "question_count": normalized.count("?"),
        "equal_count": normalized.count("="),
        "ampersand_count": normalized.count("&"),
        "at_count": normalized.count("@"),
        "percent_count": normalized.count("%"),
        "hash_count": normalized.count("#"),
        "digit_count": digits,
        "letter_count": letters,
        "special_char_count": special,
        "digit_ratio": digits / max(len(normalized), 1),
        "special_char_ratio": special / max(len(normalized), 1),
        "uses_https": int(parsed.scheme == "https"),
        "uses_http": int(parsed.scheme == "http"),
        "dangerous_scheme": int(parsed.scheme in ["javascript", "data", "file", "vbscript"]),
        "unusual_scheme": int(parsed.scheme not in ["http", "https"]),
        "has_ip_hostname": is_ip(hostname),
        "has_port": int(parsed.port is not None) if parsed.netloc else 0,
        "subdomain_depth": len([x for x in subdomain.split(".") if x]),
        "max_label_length": max([len(x) for x in labels], default=0),
        "first_label_length": len(first_label),
        "first_label_entropy": entropy(first_label),
        "first_label_vowel_ratio": vowel_ratio(first_label),
        "first_label_consonant_run": consonant_run(first_label),
        "keyword_count": sum(1 for w in SUSPICIOUS_WORDS if w in lower),
        "brand_count": sum(1 for w in BRANDS if w in lower),
        "domain_contains_brand": int(any(w in registered for w in BRANDS)),
        "keyword_in_domain": int(any(w in registered for w in SUSPICIOUS_WORDS)),
        "is_shortener": int(registered in SHORTENERS),
        "is_tracking_domain": tracking_domain,
        "suspicious_tld": suspicious_tld,
        "trusted_registered_domain": trusted_registered_domain,
        "direct_trusted_host": direct_trusted_host,
        "safe_path": safe_path,
        "url_entropy": entropy(normalized),
        "hostname_entropy": entropy(hostname),
        "decoded_differs": int(decoded != normalized),
        "double_slash_in_path": int("//" in path),
        "risky_extension": int(extension in RISKY_EXTENSIONS),
        "many_subdirectories": int(len([x for x in path.split("/") if x]) >= 5),
        "long_query": int(len(query) > 80),
        "long_fragment": int(len(fragment) > 30),
        "empty_hostname": int(not hostname),
        "localhost_reference": int(hostname in ["localhost", "127.0.0.1", "0.0.0.0"]),
        "param_count": len(all_pairs),
        "tracking_param_count": tracking_param_count,
        "affiliate_param_count": affiliate_param_count,
        "repeated_param_count": repeated_param_count,
        "numeric_param_count": numeric_param_count,
        "empty_param_count": empty_param_count,
        "hash_value_count": hash_value_count,
        "ip_value_count": ip_value_count,
        "domain_param_mismatch": domain_param_mismatch,
        "short_token_path": short_token_path,
        "click_action_fragment": click_action_fragment,
        "random_like_token_count": len(random_like_tokens),
        "long_alnum_token_count": len(long_alnum_tokens),
        "fragment_has_query_style": int("=" in fragment and ("&" in fragment or "?" in fragment)),
        "domain_length": len(parts["domain"]),
        "domain_entropy": entropy(parts["domain"]),
        "domain_vowel_ratio": vowel_ratio(parts["domain"])
    }

FEATURE_ORDER = [
    "url_length","hostname_length","path_length","query_length","fragment_length","dot_count",
    "hyphen_count","underscore_count","slash_count","question_count","equal_count","ampersand_count",
    "at_count","percent_count","hash_count","digit_count","letter_count","special_char_count",
    "digit_ratio","special_char_ratio","uses_https","uses_http","dangerous_scheme","unusual_scheme",
    "has_ip_hostname","has_port","subdomain_depth","max_label_length","first_label_length",
    "first_label_entropy","first_label_vowel_ratio","first_label_consonant_run","keyword_count",
    "brand_count","domain_contains_brand","keyword_in_domain","is_shortener","is_tracking_domain",
    "suspicious_tld","trusted_registered_domain","direct_trusted_host","safe_path","url_entropy",
    "hostname_entropy","decoded_differs","double_slash_in_path","risky_extension",
    "many_subdirectories","long_query","long_fragment","empty_hostname","localhost_reference",
    "param_count","tracking_param_count","affiliate_param_count","repeated_param_count",
    "numeric_param_count","empty_param_count","hash_value_count","ip_value_count",
    "domain_param_mismatch","short_token_path","click_action_fragment","random_like_token_count",
    "long_alnum_token_count","fragment_has_query_style","domain_length","domain_entropy",
    "domain_vowel_ratio"
]

def feature_vector(url):
    features = extract_features(url)
    return [features[name] for name in FEATURE_ORDER]
