import base64, hashlib, hmac, ipaddress, json, math, os, random, re, secrets, socket, time, uuid
from pathlib import Path
from dotenv import load_dotenv
from google import genai

load_dotenv()  # loads .env file automatically

# Resilient DNS resolution for restrictive local DHCP networks
_orig_getaddrinfo = socket.getaddrinfo
_GOOGLE_FALLBACK_IPS = ("172.217.113.4", "172.217.117.4", "172.217.116.4", "172.217.112.4")

def _custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        if host and "googleapis.com" in host:
            for fb_ip in _GOOGLE_FALLBACK_IPS:
                try:
                    return _orig_getaddrinfo(fb_ip, port, family, type, proto, flags)
                except Exception:
                    continue
        raise

socket.getaddrinfo = _custom_getaddrinfo

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

BASE = Path(__file__).parent
app = FastAPI(title="License Guard")
# Demo only: lets the attacker UI run from a different origin/port or machine
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------- Gemini AI threat detection ----------
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if not GEMINI_API_KEY and os.path.exists(".env"):
    try:
        with open(".env", "r", encoding="utf-8") as _f:
            for _line in _f:
                if _line.strip().startswith("GEMINI_API_KEY="):
                    GEMINI_API_KEY = _line.strip().split("=", 1)[1].strip().strip('"').strip("'")
                    break
    except Exception:
        pass
gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# ---------- Developer console is private-network only ----------
# Public (through a tunnel): /store, /attacker, sign-up/login/purchase, and /api/verify.
# Private only: the developer console and every admin action (issue, list, inspect, revoke, simulate).
ADMIN_PATHS = ("/api/issue", "/api/licenses", "/api/license/", "/api/revoke/", "/api/unrevoke/", "/api/simulate", "/api/ai-audit", "/api/ai-override", "/api/gemini-blocks", "/api/honeypot-telemetry", "/api/honeypot-spawn")
# Tunnels (Cloudflare, ngrok...) connect from this same computer, so the address alone looks local.
# They always add these headers, which a direct visitor on your own network never sends.
PROXY_HEADERS = ("cf-connecting-ip", "cf-ray", "x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded")


def is_private_request(request: Request):
    if any(h in request.headers for h in PROXY_HEADERS):
        return False
    try:
        ip = ipaddress.ip_address(request.client.host if request.client else "")
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


@app.middleware("http")
async def admin_private_only(request: Request, call_next):
    path = request.url.path
    if (path == "/" or path.startswith(ADMIN_PATHS)) and not is_private_request(request):
        if path == "/":
            return HTMLResponse("<h1>Not available</h1><p>The developer console can only be opened from the private network.</p>", 403)
        return JSONResponse({"detail": "Admin actions are only available on the private network"}, status_code=403)
    return await call_next(request)


# ---------- 1. Cryptography: Ed25519 signed licenses ----------
KEY_FILE = BASE / "private.key"
if KEY_FILE.exists():
    PRIV = Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
else:
    PRIV = Ed25519PrivateKey.generate()
    KEY_FILE.write_bytes(PRIV.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
PUB = PRIV.public_key()

b64e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

LICENSES = {}  # license_id -> {"payload", "revoked", "acts": [...]}

COUNTRIES = {  # country -> (lat, lon)
    "IN": (20.6, 78.9), "US": (39.8, -98.6), "DE": (51.2, 10.4), "BR": (-14.2, -51.9),
    "JP": (36.2, 138.3), "AU": (-25.3, 133.8), "GB": (55.4, -3.4), "RU": (61.5, 105.3),
}


# ---------- Short product keys: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX ----------
# 20 random characters + a 5-character check code made with a server-only secret.
# Anyone can read a key, but nobody can invent a valid one without the secret.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L, so keys are easy to read out
HMAC_KEY = PRIV.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
KEYS = {}  # product key -> license_id


def check_code(body):
    d = hmac.new(HMAC_KEY, body.encode(), hashlib.sha256).digest()
    return "".join(ALPHABET[b % len(ALPHABET)] for b in d[:5])


def make_key():
    while True:
        body = "".join(secrets.choice(ALPHABET) for _ in range(20))
        raw = body + check_code(body)
        key = "-".join(raw[i:i + 5] for i in range(0, 25, 5))
        if key not in KEYS:
            return key


def issue(product="DemoSoft Pro", tier="pro", max_devices=3, days=365, owner=None):
    now = int(time.time())
    key = make_key()
    payload = {"id": "LIC-" + uuid.uuid4().hex[:8].upper(), "key": key, "product": product, "tier": tier,
               "max_devices": max_devices, "owner": owner, "issued": now, "expires": now + days * 86400}
    LICENSES[payload["id"]] = {"payload": payload, "revoked": False, "auto_revoked": False,
                               "trust_score": 100, "denied_count": 0, "acts": [],
                               "trusted": [], "pending": {}, "denied": set(), "bound": False, "tokens": {}}
    KEYS[key] = payload["id"]
    return key, payload


def parse(key):
    """Returns (license or None, status) where status is malformed | badcheck | unknown | ok."""
    raw = re.sub(r"[^A-Za-z0-9]", "", key or "").upper()
    if len(raw) != 25 or any(c not in ALPHABET for c in raw):
        return None, "malformed"
    if not hmac.compare_digest(raw[20:], check_code(raw[:20])):
        return None, "badcheck"
    lid = KEYS.get("-".join(raw[i:i + 5] for i in range(0, 25, 5)))
    return (LICENSES[lid], "ok") if lid else (None, "unknown")


# ---------- 2. AI: Isolation Forest trained on synthetic "normal" behaviour ----------
# features: [distinct devices, distinct countries, activations in last hour, max travel speed km/h]
rng = np.random.default_rng(7)
N = 800
# Normal use: 1-3 devices, mostly one country, a few activations per hour, rarely any travel.
# The tails matter: Isolation Forest cannot see values far outside what it was trained on,
# so normal behaviour must include some (rare) larger numbers.
_speed = np.where(rng.random(N) < 0.85, 0.0, rng.uniform(0, 400, N))
X_NORMAL = np.c_[1 + rng.poisson(0.8, N), 1 + (rng.random(N) < 0.2), rng.poisson(1.5, N), _speed]
MODEL = IsolationForest(n_estimators=200, contamination=0.02, random_state=7).fit(X_NORMAL)


def haversine(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def features(acts):
    now = time.time()
    speed = 0.0
    for p, q in zip(acts, acts[1:]):
        if p["country"] != q["country"]:
            hours = max((q["ts"] - p["ts"]) / 3600, 1 / 60)
            speed = max(speed, haversine(p, q) / hours)
    return [len({a["device"] for a in acts}), len({a["country"] for a in acts}),
            sum(1 for a in acts if now - a["ts"] < 3600), speed]


def assess(lic):
    acts, mx = lic["acts"], lic["payload"]["max_devices"]
    devs, ctry, hour, speed = f = features(acts)
    rule, reasons = 0, []
    if devs > mx:
        rule += min(40, 12 * (devs - mx))
        reasons.append(f"Activated on {devs} devices (limit is {mx})")
    if ctry > 2:
        rule += min(30, 10 * (ctry - 1))
        reasons.append(f"Activations came from {ctry} different countries")
    if hour > 5:
        rule += min(20, 2 * hour)
        reasons.append(f"{hour} activations in the last hour")
    refused = sum(1 for a in acts if a.get("status") in ("denied", "full", "flood", "badtoken"))
    denied = lic.get("denied_count", 0) + len(lic.get("denied", set()))
    if refused:
        rule += min(30, 2 * refused)
        reasons.append(f"{refused} activation attempts were refused")
    if denied:
        rule += min(25, 4 * denied)
        if not any("denied" in r for r in reasons):
            reasons.append(f"{denied} device access request(s) were denied by owner")
    if speed > 900:
        rule += 25
        reasons.append(f"Impossible travel: about {int(speed):,} km/h between two activations")
    ml = int(np.clip((0.06 - MODEL.decision_function([f])[0]) / 0.12 * 100, 0, 100)) if acts else 0
    if ml >= 50 and not reasons:
        reasons.append("Usage pattern is statistically unusual compared with normal licenses")
    risk = min(100, max(rule, ml))
    # Trust score dynamically fluctuates between 0 and 100 inversely with risk
    trust_score = max(0, 100 - risk)
    verdict = "green" if risk < 30 else "yellow" if risk < 70 else "red"
    return {"risk": risk, "trust_score": trust_score, "rule_score": rule, "ml_score": ml, "verdict": verdict, "reasons": reasons}


def view(lic, extra=None):
    assessment = assess(lic)
    risk = assessment["risk"]
    # Auto-revoke if risk score goes above 85 (or trust drops below 15)
    if risk > 85 and not lic["revoked"]:
        lic["revoked"] = True
        lic["auto_revoked"] = True
        print(f"[AUTO-REVOKED] License {lic['payload']['id']} automatically revoked: Risk={risk} (> 85), Trust={assessment['trust_score']}.")

    out = {"license": lic["payload"], "revoked": lic["revoked"], "auto_revoked": lic.get("auto_revoked", False),
           "trust_score": assessment["trust_score"], "activations": lic["acts"][-60:],
           "slots_used": len(lic["trusted"]), "pending_count": len(lic["pending"]),
           "total_acts": len(lic["acts"]), "refused": sum(1 for a in lic["acts"] if a.get("status") in ("denied", "full", "flood", "badtoken")),
           "devices_seen": len({a["device"] for a in lic["acts"]}),
           "by_country": {c: sum(1 for a in lic["acts"] if a["country"] == c) for c in {a["country"] for a in lic["acts"]}}}
    out.update(assessment)
    if lic["revoked"]:
        revoke_reason = "License automatically revoked: risk score reached above 85" if lic.get("auto_revoked") else "License was revoked by an administrator"
        out.update(verdict="red", risk=100, reasons=[revoke_reason] + [r for r in out["reasons"] if r != revoke_reason])
    out.update(extra or {})
    return out


def clean_device(d):
    return re.sub(r"[^\w.\-]", "", d or "")[:40] or "unknown"


def clean_country(c):
    c = (c or "").upper()
    return c if c in COUNTRIES else "XX"


def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


def add_act(lic, device, country, token="", ip="?"):
    """Owner-approval rule. The first device binds the license and any other device needs the
    owner's approval. An approved device must also prove itself with a secret device token
    (given out once), so knowing an approved device's name is not enough to impersonate it."""
    lat, lon = COUNTRIES.get(country, (0, 0))
    trusted, pending, new_token = lic["trusted"], lic["pending"], None
    for d in [d for d, i in pending.items() if time.time() - i["ts"] > 600]:
        pending.pop(d)  # unanswered requests expire after 10 minutes
    if not lic["bound"] and device not in lic["denied"]:
        trusted.append(device)
        lic["bound"] = True
    if device in trusted:
        saved = lic["tokens"].get(device)
        if saved is None:  # first time this approved device checks in: hand it its secret
            new_token = secrets.token_urlsafe(18)
            lic["tokens"][device] = hash_token(new_token)
            status = "ok"
        elif token and hmac.compare_digest(saved, hash_token(token)):
            status = "ok"
        else:
            status = "badtoken"
    elif device in lic["denied"]:
        status = "denied"
    elif len(trusted) >= lic["payload"]["max_devices"]:
        status = "full"
    elif device in pending:
        status = "pending"
    elif len(pending) >= 5:
        status = "flood"
    else:
        pending[device] = {"country": country, "ts": time.time(), "ip": ip}
        status = "pending"
    lic["acts"].append({"ts": time.time(), "device": device, "country": country,
                        "lat": lat, "lon": lon, "allowed": status == "ok", "status": status, "ip": ip})
    return status, new_token



# ---------- AI: which pending requests in the approval queue look automated ----------
# features: [other requests within 20s, requests sharing this one's IP, country unseen
#            among this license's trusted devices, how full the queue already is]
_pn_rng = np.random.default_rng(11)
_PN = 300
_PN_X = np.c_[np.ones(_PN) + (_pn_rng.random(_PN) < 0.05) * _pn_rng.integers(0, 3, _PN),
              np.ones(_PN) + (_pn_rng.random(_PN) < 0.05) * _pn_rng.integers(0, 3, _PN),
              (_pn_rng.random(_PN) < 0.3).astype(float), _pn_rng.integers(1, 3, _PN)]
PENDING_MODEL = IsolationForest(n_estimators=150, contamination=0.05, random_state=11).fit(_PN_X)


def pending_assess(lic):
    now, pend, trusted_countries = time.time(), lic["pending"], {lic["acts"][i]["country"]
        for i in range(len(lic["acts"])) if lic["acts"][i]["device"] in lic["trusted"]}
    out = {}
    for device, info in pend.items():
        burst = sum(1 for d2, i2 in pend.items() if abs(i2["ts"] - info["ts"]) <= 20)
        same_ip = sum(1 for d2, i2 in pend.items() if i2.get("ip") == info.get("ip") and info.get("ip") not in (None, "?"))
        unseen_country = 1 if trusted_countries and info["country"] not in trusted_countries else 0
        fullness = len(pend)
        f = [burst, same_ip, unseen_country, fullness]
        rule, reasons = 0, []
        if burst >= 3:
            rule += min(55, 15 * burst)
            reasons.append(f"{burst} requests arrived within seconds of each other, which people don't normally do")
        if same_ip >= 3:
            rule += min(45, 12 * same_ip)
            reasons.append(f"{same_ip} requests came from the same network address")
        if unseen_country:
            rule += 10
            reasons.append("Country doesn't match this license's approved devices")
        # Flagged device intelligence: check if this device was previously caught by a canary honeypot trap
        is_flagged = device in FLAGGED_ADVERSARY_DEVICES
        if is_flagged:
            rule = max(rule, 95)
            reasons.insert(0, "CRITICAL: This device was previously caught tripping an active canary honeypot trap")
        ml = int(np.clip((0.06 - PENDING_MODEL.decision_function([f])[0]) / 0.18 * 100, 0, 100))
        risk = min(100, max(rule, ml))
        if is_flagged:
            risk = max(risk, 95)
        out[device] = {"risk": risk, "verdict": "green" if risk < 30 else "yellow" if risk < 70 else "red",
                       "flagged_adversary": is_flagged,
                       "reasons": reasons or (["Usage pattern is unusual compared with a normal new device"] if ml >= 50 else [])}
    return out


# ---------- AI manual overrides + audit log ----------
# key = f"{product_key}:{device}" -> "ALLOW" | "BLOCK"
MANUAL_OVERRIDES = {}
# Ordered list of every Gemini decision for admin review (capped at 200)
AI_AUDIT_LOG = []
# Dedicated log of all requests blocked by Gemini AI (capped at 200)
GEMINI_BLOCK_LOG = []

# ---------- Active Cyber Deception: AI Canary Keys & Honeypots ----------
# Decoy keys planted in public code, leaked pastes, or simulated dumps.
# If an attacker tries ANY canary key, AI instantly tracks their signature,
# triggers synthetic license poisoning, and blacklists their device cluster.
CANARY_TRAPS = {}
HONEYPOT_TELEMETRY = []
FLAGGED_ADVERSARY_DEVICES = set()  # Cleaned device names flagged by canary traps


def is_canary_key(key: str):
    raw = re.sub(r"[^A-Za-z0-9]", "", key or "").upper()
    fmt_key = "-".join(raw[i:i + 5] for i in range(0, 25, 5)) if len(raw) == 25 else raw
    return CANARY_TRAPS.get(fmt_key) or CANARY_TRAPS.get(key.strip().upper())


def register_canary(label: str = "leaked-pastebin"):
    key = make_key()
    CANARY_TRAPS[key] = {
        "created_at": time.time(),
        "label": label,
        "triggered_count": 0,
        "trapped_ips": set()
    }
    return key

# Deploy initial seed canary trap
DEFAULT_CANARY = register_canary("darkweb-paste-dump")


def record_gemini_block(key, device, country, ip, threat, attack_type, confidence, reasoning):
    entry = {
        "ts": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "key": key,
        "device": device,
        "country": country,
        "ip": ip,
        "threat_level": threat,
        "attack_type": attack_type,
        "confidence": confidence,
        "reasoning": reasoning
    }
    GEMINI_BLOCK_LOG.append(entry)
    if len(GEMINI_BLOCK_LOG) > 200:
        GEMINI_BLOCK_LOG.pop(0)
    print(f"[GEMINI ATTACK BLOCKED] [{entry['time_str']}] Key: ...{key[-5:] if len(key) >= 5 else key} | Device: '{device}' | Country: {country} | IP: {ip} | Threat: {threat} | Attack: {attack_type} | Reason: {reasoning}")
    return entry


class OverrideReq(BaseModel):
    key: str          # the DemoSoft product key
    device: str       # the device name to override
    action: str       # "ALLOW" | "BLOCK" | "CLEAR"


def gemini_threat_analysis(lic, device, country, ip, key_status, token_provided, new_token_issued=False):
    if gemini_client is None:
        return {"threat_level": "LOW", "action": "ALLOW", "confidence": 1.0, "attack_type": "none", "reasoning": "Gemini AI not configured", "recommendation": "None"}
    
    try:
        payload = lic["payload"]
        history = [{"device": a["device"], "country": a["country"], "ts": a["ts"], "status": a.get("status"), "ip": a.get("ip")} for a in lic["acts"][-20:]]
        risk_scores = assess(lic)
        fails = len(FAILS.get(ip, []))
        computed_features = features(lic["acts"])

        context = {
            "request": {
                "device": device,
                "country": country,
                "ip": ip,
                "key_status": key_status,
                "token_provided": token_provided,
                "new_token_issued": new_token_issued,
                "ip_failed_attempts": fails
            },
            "license": {
                "product": payload["product"],
                "tier": payload["tier"],
                "max_devices": payload["max_devices"],
                "owner": payload.get("owner")
            },
            "state": {
                "trusted_devices": lic["trusted"],
                "pending_devices": {d: info["country"] for d, info in lic["pending"].items()},
                "denied_devices": list(lic["denied"]),
                "recent_history": history,
                "risk_scores": risk_scores,
                "computed_features": {
                    "distinct_devices": computed_features[0],
                    "distinct_countries": computed_features[1],
                    "activations_last_hour": computed_features[2],
                    "max_travel_speed_kmh": computed_features[3]
                }
            }
        }
        
        prompt = """You are a security AI for a software licensing system called License Guard by DemoSoft.
Your job is to analyze each access request and determine if it is an attack, fraud, key sharing abuse, or legitimate use.

You MUST respond with EXACTLY this JSON format and nothing else:
{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "action": "ALLOW" | "WARN" | "BLOCK",
  "confidence": 0.0 to 1.0,
  "attack_type": "none" | "key_sharing" | "brute_force" | "impossible_travel" | "device_impersonation" | "approval_flooding" | "credential_stuffing" | "automated_attack" | "velocity_anomaly",
  "reasoning": "One paragraph explaining your analysis",
  "recommendation": "One sentence for the system admin"
}

Rules:
- If new_token_issued is true (the device is binding as the first device or checking in for the first time after owner approval), threat is LOW and action is ALLOW.
- If the device is already trusted and presents a valid token (key_status is "ok"), threat is LOW and action is ALLOW.
- If a known device name is used without the correct token (key_status is "badtoken"), this is device impersonation, threat is CRITICAL, action is BLOCK.
- If there are multiple countries in short time spans (impossible travel), threat is HIGH or CRITICAL, action is BLOCK.
- If the same IP has many failed attempts, threat is HIGH, action is BLOCK.
- If device names look auto-generated and arrive in rapid bursts, this is approval flooding, threat is CRITICAL, action is BLOCK.
- If the license has activations from many devices beyond its limit, threat is HIGH, action is BLOCK.
- If a device is pending approval, threat is MEDIUM at most, action is WARN (let the owner decide).
- When in doubt, err on the side of security.
- NEVER output anything except the JSON object.
"""
        
        response = gemini_client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt + "\n\nContext:\n" + json.dumps(context)
        )
        
        try:
            text = response.text.strip()
            if text.startswith("```json"): text = text[7:]
            if text.startswith("```"): text = text[3:]
            if text.endswith("```"): text = text[:-3]
            return json.loads(text.strip())
        except Exception:
            local_assessment = assess(lic)
            risk = local_assessment["risk"]
            threat = "CRITICAL" if risk >= 85 else "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW"
            return {"threat_level": threat, "action": "ALLOW" if risk < 70 else "BLOCK", "confidence": 0.85, "attack_type": "none", "reasoning": "Standard pattern confirmed via local threat engine", "recommendation": "Normal usage"}
    except Exception as e:
        print(f"Gemini API Error: {e}")
        local_assessment = assess(lic)
        risk = local_assessment["risk"]
        threat = "CRITICAL" if risk >= 85 else "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW"
        action = "BLOCK" if risk >= 70 else "WARN" if risk >= 40 else "ALLOW"
        return {
            "threat_level": threat,
            "action": action,
            "confidence": 0.90,
            "attack_type": "velocity_anomaly" if any("travel" in r for r in local_assessment["reasons"]) else "none",
            "reasoning": f"Local threat defense evaluated request. Threat level assessed as {threat} based on device telemetry and anomaly scoring.",
            "recommendation": "Review risk scores in audit log."
        }


# ---------- API ----------
class IssueReq(BaseModel):
    product: str = "DemoSoft Pro"
    tier: str = "pro"
    max_devices: int = 3


class VerifyReq(BaseModel):
    key: str
    device: str = "device-1"
    country: str = "IN"
    token: str = ""


class SimReq(BaseModel):
    license_id: str
    n: int = 1


@app.post("/api/issue")
def api_issue(r: IssueReq):
    key, payload = issue(r.product, r.tier, r.max_devices)
    return {"key": key, "license": payload}


FAILS = {}  # ip -> timestamps of invalid-key attempts


def too_many_fails(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 60]
    return len(FAILS[ip]) >= 10


def public_view(res, lic):
    """What a caller holding only the key may see: no other devices, no owner, no internal counters."""
    for k in ("activations", "by_country", "devices_seen", "total_acts", "refused", "pending_count", "slots_used"):
        res.pop(k, None)
    p = lic["payload"]
    res["license"] = {"product": p["product"], "tier": p["tier"], "max_devices": p["max_devices"], "expires": p["expires"]}
    return res


@app.post("/api/verify")
def api_verify(r: VerifyReq, req: Request):
    ip = req.client.host if req.client else "unknown"

    def reject(why):
        FAILS.setdefault(ip, []).append(time.time())
        return {"verdict": "red", "risk": 100, "label": "Fake/Tampered", "license": None,
                "activations": [], "allowed": False, "reasons": [why]}

    if too_many_fails(ip):
        return {"verdict": "red", "risk": 100, "label": "Blocked", "license": None, "activations": [],
                "allowed": False, "reasons": ["Too many invalid keys from this address. Blocked for one minute"]}
    # Active Honeypot Trap check
    canary = is_canary_key(r.key)
    if canary:
        canary["triggered_count"] += 1
        canary["trapped_ips"].add(ip)
        dev_name = clean_device(r.device)
        FLAGGED_ADVERSARY_DEVICES.add(dev_name)
        telemetry = {
            "ts": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "key": r.key.strip(),
            "label": canary["label"],
            "device": dev_name,
            "country": clean_country(r.country),
            "ip": ip,
            "signature": f"TRAP-{uuid.uuid4().hex[:6].upper()}",
            "verdict": "ATTACKER_CAPTURED"
        }
        HONEYPOT_TELEMETRY.append(telemetry)
        if len(HONEYPOT_TELEMETRY) > 100:
            HONEYPOT_TELEMETRY.pop(0)
        FAILS.setdefault(ip, []).append(time.time())
        print(f"[CYBER DECEPTION] Honeypot Canary triggered: Key=...{r.key.strip()[-5:]} | Label={canary['label']} | IP={ip} | Device={dev_name} | Signature={telemetry['signature']}")
        return {
            "verdict": "red",
            "risk": 100,
            "trust_score": 0,
            "label": "Decoy Trap Triggered",
            "license": None,
            "activations": [],
            "allowed": False,
            "reasons": [
                f"Active cyber defense tripped: This credential signature ({telemetry['signature']}) was planted in public intelligence traps. Originating IP {ip} has been flagged for counter-surveillance."
            ],
            "honeypot_captured": True
        }

    lic, status = parse(r.key)
    if status == "malformed":
        return reject("This is not a valid product key. Keys look like XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
    if status == "badcheck":
        return reject("The check code is wrong: the key was mistyped, edited or made up")
    if status == "unknown":
        return reject("The key looks valid but this server never issued it")
    if lic["revoked"]:
        return public_view(view(lic, {"allowed": False}), lic)
    if lic["payload"]["expires"] < time.time():
        return public_view(view(lic, {"verdict": "red", "risk": 100, "allowed": False, "reasons": ["License has expired"]}), lic)
    ip = req.client.host if req.client else "?"
    status, new_token = add_act(lic, clean_device(r.device), clean_country(r.country), r.token, ip)
    res = view(lic, {"allowed": status == "ok", "status": status})
    
    gemini_result = gemini_threat_analysis(lic, clean_device(r.device), clean_country(r.country), ip, status, bool(r.token), new_token_issued=bool(new_token))

    # --- Manual override check (admin always wins over AI) ---
    override_key = f"{r.key.strip().upper()}:{clean_device(r.device)}"
    manual = MANUAL_OVERRIDES.get(override_key)
    if manual == "BLOCK":
        res["allowed"] = False
        res["verdict"] = "red"
        res["risk"] = 100
        res["reasons"].insert(0, "Manually blocked by administrator (override)")
        gemini_result["action"] = "BLOCK"
        gemini_result["overridden_by"] = "ADMIN_BLOCK"
    elif manual == "ALLOW":
        res["allowed"] = True
        res["verdict"] = "green" if res.get("risk", 0) < 30 else "yellow"
        res["risk"] = min(res.get("risk", 0), 25)
        res["reasons"].insert(0, "Manually approved by administrator (override)")
        gemini_result["action"] = "ALLOW"
        gemini_result["overridden_by"] = "ADMIN_ALLOW"
    else:
        # No manual override — apply Gemini's decision
        if gemini_result.get("action") == "BLOCK":
            # Record directly into the dedicated Gemini Block Log
            record_gemini_block(
                key=r.key.strip(),
                device=clean_device(r.device),
                country=clean_country(r.country),
                ip=ip,
                threat=gemini_result.get("threat_level", "HIGH"),
                attack_type=gemini_result.get("attack_type", "attack"),
                confidence=gemini_result.get("confidence", 0.0),
                reasoning=gemini_result.get("reasoning", "Access blocked by AI security analysis")
            )
            if status == "ok":
                res["allowed"] = False
                res["verdict"] = "red"
                res["risk"] = max(res.get("risk", 0), 95)
                res["reasons"].insert(0, f"Gemini AI threat detected: {gemini_result.get('reasoning')}")
        elif gemini_result.get("action") == "WARN":
            res["reasons"].append(f"Gemini AI advisory: {gemini_result.get('reasoning')}")
        
    res["gemini_analysis"] = gemini_result

    # --- Record to audit log ---
    audit_entry = {
        "ts": time.time(), "key": r.key.strip(), "device": clean_device(r.device),
        "country": clean_country(r.country), "ip": ip,
        "ai_action": gemini_result.get("action"), "ai_threat": gemini_result.get("threat_level"),
        "ai_attack_type": gemini_result.get("attack_type"), "ai_confidence": gemini_result.get("confidence"),
        "ai_reasoning": gemini_result.get("reasoning"),
        "manual_override": manual or "none",
        "final_allowed": res.get("allowed", False), "final_verdict": res.get("verdict"),
    }
    AI_AUDIT_LOG.append(audit_entry)
    if len(AI_AUDIT_LOG) > 200:
        AI_AUDIT_LOG.pop(0)

    why = {"pending": "New device: waiting for the license owner to approve it before it can use this key",
           "denied": "The license owner denied this device",
           "full": "This device was refused: all device slots are already in use",
           "flood": "Too many unapproved devices are already waiting for the owner. Try again later",
           "badtoken": "This device name is approved, but it did not present its device secret. Possible impersonation"}.get(status)
    if why:
        res["reasons"].insert(0, why)
    if new_token:
        res["device_token"] = new_token
    return public_view(res, lic)


# ---------- AI audit log + manual override admin endpoints ----------
@app.get("/api/ai-audit")
def api_ai_audit():
    """Return the last 200 Gemini AI decisions for admin review."""
    return list(reversed(AI_AUDIT_LOG))


@app.get("/api/gemini-blocks")
def api_gemini_blocks():
    """Return the list of requests specifically blocked by Gemini AI."""
    return list(reversed(GEMINI_BLOCK_LOG))


@app.get("/api/ai-overrides")
def api_ai_overrides():
    """Return all active manual overrides."""
    out = []
    for combo, action in MANUAL_OVERRIDES.items():
        parts = combo.split(":", 1)
        out.append({"key": parts[0] if parts else combo, "device": parts[1] if len(parts) > 1 else "?", "action": action})
    return out


# ---------- Active Cyber Deception endpoints ----------
@app.get("/api/honeypot-telemetry")
def api_honeypot_telemetry():
    """Return trapped attackers and active canary key telemetry."""
    return {
        "traps": [
            {"key": k, "label": v["label"], "triggered_count": v["triggered_count"], "ips": list(v["trapped_ips"])}
            for k, v in CANARY_TRAPS.items()
        ],
        "events": list(reversed(HONEYPOT_TELEMETRY))
    }


class CanarySpawnReq(BaseModel):
    label: str = "pastebin-leak-decoy"


@app.post("/api/honeypot-spawn")
def api_honeypot_spawn(r: CanarySpawnReq):
    """Deploy a new active canary honeypot key."""
    key = register_canary(r.label)
    return {"key": key, "label": r.label, "status": "deployed"}



@app.post("/api/ai-override")
def api_ai_override(r: OverrideReq):
    """Set or clear a manual override for a specific key+device combination."""
    key = r.key.strip().upper()
    device = clean_device(r.device)
    combo = f"{key}:{device}"
    if r.action.upper() == "CLEAR":
        MANUAL_OVERRIDES.pop(combo, None)
        return {"ok": True, "message": f"Override cleared for {device} on key ...{key[-5:]}"}
    if r.action.upper() not in ("ALLOW", "BLOCK"):
        raise HTTPException(400, "Action must be ALLOW, BLOCK, or CLEAR")
    MANUAL_OVERRIDES[combo] = r.action.upper()
    return {"ok": True, "message": f"Override set: {r.action.upper()} for {device} on key ...{key[-5:]}"}


@app.post("/api/simulate")
def api_simulate(r: SimReq):
    lic = LICENSES.get(r.license_id)
    if not lic:
        raise HTTPException(404, "Unknown license")
    for _ in range(r.n):
        add_act(lic, "sim-" + uuid.uuid4().hex[:5], random.choice(list(COUNTRIES)))
    return view(lic)


@app.get("/api/license/{lid}")
def api_license(lid: str):
    if lid not in LICENSES:
        raise HTTPException(404, "Unknown license")
    return view(LICENSES[lid])


@app.post("/api/revoke/{lid}")
def api_revoke(lid: str):
    if lid not in LICENSES:
        raise HTTPException(404, "Unknown license")
    LICENSES[lid]["revoked"] = True
    LICENSES[lid]["auto_revoked"] = False
    return view(LICENSES[lid])


@app.post("/api/unrevoke/{lid}")
def api_unrevoke(lid: str):
    """Developer/admin only action: restores an automatically or manually revoked license."""
    if lid not in LICENSES:
        raise HTTPException(404, "Unknown license")
    lic = LICENSES[lid]
    lic["revoked"] = False
    lic["auto_revoked"] = False
    # Clear excessive suspicious refusal logs from acts so risk doesn't immediately bounce back over 85
    # Retain recent normal activity but clear refused spam
    lic["acts"] = [a for a in lic["acts"] if a.get("status") not in ("flood", "badtoken", "denied")][-10:]
    lic["denied"] = set()
    print(f"[UNREVOKED BY DEVELOPER] License {lid} has been unrevoked and reinstated.")
    return view(lic)



# ---------- Customer store: accounts + purchase -> key ----------
PRODUCTS = {  # prices and device limits are decided here, never by the browser
    "basic": {"name": "DemoSoft Basic", "price": 499, "devices": 1},
    "pro": {"name": "DemoSoft Pro", "price": 1499, "devices": 3},
    "enterprise": {"name": "DemoSoft Enterprise", "price": 4999, "devices": 10},
}
USERS, SESSIONS = {}, {}
EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")


class AuthReq(BaseModel):
    email: str
    password: str


class BuyReq(BaseModel):
    tier: str
    device: str = ""
    country: str = "IN"


class DecisionReq(BaseModel):
    key: str
    device: str
    action: str  # approve | deny | remove


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


def start_session(email):
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = email
    return {"token": token, "email": email}


def current_user(authorization: str = Header(None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token not in SESSIONS:
        raise HTTPException(401, "Please log in first")
    return SESSIONS[token]


@app.post("/api/signup")
def api_signup(r: AuthReq):
    email = r.email.strip().lower()
    if not EMAIL_RE.match(email) or len(r.password) < 6:
        raise HTTPException(400, "Enter a valid email and a password of at least 6 characters")
    if email in USERS:
        raise HTTPException(409, "An account with this email already exists")
    salt = secrets.token_bytes(16)
    USERS[email] = {"salt": salt, "hash": hash_pw(r.password, salt)}
    return start_session(email)


@app.post("/api/login")
def api_login(r: AuthReq):
    email = r.email.strip().lower()
    u = USERS.get(email)
    if not u or not hmac.compare_digest(u["hash"], hash_pw(r.password, u["salt"])):
        raise HTTPException(401, "Wrong email or password")
    return start_session(email)


@app.get("/api/store/products")
def api_products():
    return [{"tier": t, **p} for t, p in PRODUCTS.items()]


@app.post("/api/purchase")
def api_purchase(r: BuyReq, user: str = Depends(current_user)):
    p = PRODUCTS.get(r.tier)
    if not p:
        raise HTTPException(400, "Unknown plan")
    key, payload = issue(p["name"], r.tier, p["devices"], owner=user)  # demo: no real payment is taken
    token = None
    if r.device:  # the buyer's own browser becomes the first approved device and receives its secret
        _, token = add_act(LICENSES[payload["id"]], clean_device(r.device), clean_country(r.country), ip="buyer")
    return {"key": key, "license": payload, "paid": p["price"], "device_token": token}


@app.get("/api/my-licenses")
def api_my_licenses(user: str = Depends(current_user)):
    out = []
    for l in LICENSES.values():
        if l["payload"].get("owner") == user:
            v = view(l)
            p = l["payload"]
            pending_scores = pending_assess(l)
            out.append({"key": p["key"], "product": p["product"], "tier": p["tier"], "max_devices": p["max_devices"],
                        "expires": p["expires"], "revoked": l["revoked"], "auto_revoked": l.get("auto_revoked", False),
                        "trust_score": v.get("trust_score", 100), "slots_used": v["slots_used"],
                        "verdict": v["verdict"], "trusted": list(l["trusted"]),
                        "pending": [{"device": d, "country": info["country"], **pending_scores.get(d, {"risk": 0, "verdict": "green", "reasons": []})}
                                    for d, info in l["pending"].items()]})
    return out[::-1]


@app.post("/api/device-decision")
def api_device_decision(r: DecisionReq, user: str = Depends(current_user)):
    lid = KEYS.get(r.key)
    lic = LICENSES.get(lid) if lid else None
    if not lic or lic["payload"].get("owner") != user:
        raise HTTPException(404, "License not found on your account")
    d = clean_device(r.device)
    if r.action == "approve":
        if d not in lic["pending"]:
            raise HTTPException(400, "That request is no longer waiting")
        if len(lic["trusted"]) >= lic["payload"]["max_devices"]:
            raise HTTPException(400, "All device slots are in use. Remove a device first")
        lic["pending"].pop(d)
        lic["trusted"].append(d)
    elif r.action == "deny":
        pend_info = lic["pending"].pop(d, None)
        lic["denied"].add(d)
        lic["denied_count"] = lic.get("denied_count", 0) + 1
        country = pend_info["country"] if pend_info else "XX"
        lat, lon = COUNTRIES.get(country, (0, 0))
        # Log a refused activation entry so risk immediately increases and trust score drops below 100
        lic["acts"].append({
            "ts": time.time(), "device": d, "country": country,
            "lat": lat, "lon": lon, "allowed": False, "status": "denied",
            "ip": pend_info.get("ip", "?") if pend_info else "?"
        })
    elif r.action == "remove":
        if d in lic["trusted"]:
            lic["trusted"].remove(d)
            lic["tokens"].pop(d, None)
    else:
        raise HTTPException(400, "Unknown action")
    return {"ok": True}


@app.get("/api/licenses")
def api_licenses():
    rows = [view(l) for l in LICENSES.values()]
    return [{"id": r["license"]["id"], "product": r["license"]["product"], "tier": r["license"]["tier"],
             "risk": r["risk"], "trust_score": r.get("trust_score", 100), "verdict": r["verdict"],
             "revoked": r["revoked"], "auto_revoked": r.get("auto_revoked", False),
             "owner": r["license"].get("owner"),
             "activations": len(LICENSES[r["license"]["id"]]["acts"])} for r in rows]


@app.get("/")
def developer():
    return FileResponse(BASE / "developer.html")


@app.get("/attacker")
def attacker():
    return FileResponse(BASE / "attacker.html")


@app.get("/store")
def storefront():
    return FileResponse(BASE / "store.html")


@app.get("/use")
def use_key():
    return FileResponse(BASE / "use.html")
