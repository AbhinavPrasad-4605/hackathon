import base64, hashlib, hmac, ipaddress, json, math, random, re, secrets, time, uuid
from pathlib import Path

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

# ---------- Developer console is private-network only ----------
# Public (through a tunnel): /store, /attacker, sign-up/login/purchase, and /api/verify.
# Private only: the developer console and every admin action (issue, list, inspect, revoke, simulate).
ADMIN_PATHS = ("/api/issue", "/api/licenses", "/api/license/", "/api/revoke/", "/api/simulate")
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
    LICENSES[payload["id"]] = {"payload": payload, "revoked": False, "acts": []}
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
    refused = sum(1 for a in acts if not a.get("allowed", True))
    if refused:
        rule += min(40, 3 * refused)
        reasons.append(f"{refused} activation attempts were refused")
    if speed > 900:
        rule += 25
        reasons.append(f"Impossible travel: about {int(speed):,} km/h between two activations")
    ml = int(np.clip((0.06 - MODEL.decision_function([f])[0]) / 0.12 * 100, 0, 100)) if acts else 0
    if ml >= 50 and not reasons:
        reasons.append("Usage pattern is statistically unusual compared with normal licenses")
    risk = min(100, max(rule, ml))
    verdict = "green" if risk < 30 else "yellow" if risk < 70 else "red"
    return {"risk": risk, "rule_score": rule, "ml_score": ml, "verdict": verdict, "reasons": reasons}


def view(lic, extra=None):
    out = {"license": lic["payload"], "revoked": lic["revoked"], "activations": lic["acts"][-60:],
           "slots_used": min(len({a["device"] for a in lic["acts"]}), lic["payload"]["max_devices"]),
           "total_acts": len(lic["acts"]), "refused": sum(1 for a in lic["acts"] if not a["allowed"]),
           "devices_seen": len({a["device"] for a in lic["acts"]}),
           "by_country": {c: sum(1 for a in lic["acts"] if a["country"] == c) for c in {a["country"] for a in lic["acts"]}}}
    out.update(assess(lic))
    if lic["revoked"]:
        out.update(verdict="red", risk=100, reasons=["License was revoked by an administrator"] + out["reasons"])
    out.update(extra or {})
    return out


def add_act(lic, device, country):
    lat, lon = COUNTRIES.get(country, (0, 0))
    known = [a["device"] for a in lic["acts"]]
    slots = []
    for d in known:
        if d not in slots:
            slots.append(d)
    allowed = device in slots or len(slots) < lic["payload"]["max_devices"]
    lic["acts"].append({"ts": time.time(), "device": device, "country": country,
                        "lat": lat, "lon": lon, "allowed": allowed})
    return allowed


# ---------- API ----------
class IssueReq(BaseModel):
    product: str = "DemoSoft Pro"
    tier: str = "pro"
    max_devices: int = 3


class VerifyReq(BaseModel):
    key: str
    device: str = "device-1"
    country: str = "IN"


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
    lic, status = parse(r.key)
    if status == "malformed":
        return reject("This is not a valid product key. Keys look like XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
    if status == "badcheck":
        return reject("The check code is wrong: the key was mistyped, edited or made up")
    if status == "unknown":
        return reject("The key looks valid but this server never issued it")
    if lic["revoked"]:
        return view(lic, {"allowed": False})
    if lic["payload"]["expires"] < time.time():
        return view(lic, {"verdict": "red", "risk": 100, "allowed": False, "reasons": ["License has expired"]})
    allowed = add_act(lic, r.device, r.country)
    res = view(lic, {"allowed": allowed})
    if not allowed:
        res["reasons"].insert(0, "This device was refused: all device slots are already in use")
    return res


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
    return view(LICENSES[lid])


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
    return {"key": key, "license": payload, "paid": p["price"]}


@app.get("/api/my-licenses")
def api_my_licenses(user: str = Depends(current_user)):
    out = []
    for l in LICENSES.values():
        if l["payload"].get("owner") == user:
            v = view(l)
            p = l["payload"]
            out.append({"key": p["key"], "product": p["product"], "tier": p["tier"], "max_devices": p["max_devices"],
                        "expires": p["expires"], "revoked": l["revoked"], "slots_used": v["slots_used"],
                        "verdict": v["verdict"]})
    return out[::-1]


@app.get("/api/licenses")
def api_licenses():
    rows = [view(l) for l in LICENSES.values()]
    return [{"id": r["license"]["id"], "product": r["license"]["product"], "tier": r["license"]["tier"],
             "risk": r["risk"], "verdict": r["verdict"], "revoked": r["revoked"], "owner": r["license"].get("owner"),
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
