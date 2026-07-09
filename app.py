import datetime as dt
import os
import re
import secrets
import string
import uuid
from decimal import Decimal, InvalidOperation
from functools import wraps
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request
from flask_cors import CORS
from supabase import Client, create_client
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DOMAIN = os.getenv("PUBLIC_DOMAIN", "nexconnect.onrender.com")
BASE_URL = f"https://{DOMAIN}"
JWT_ALGORITHM = "HS256"
JWT_EXP_DAYS = int(os.getenv("JWT_EXP_DAYS", "14"))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

if not SUPABASE_URL or not SUPABASE_KEY or not JWT_SECRET:
    raise RuntimeError("SUPABASE_URL, SUPABASE_KEY, and JWT_SECRET must be configured.")

app = Flask(__name__, template_folder="templates")
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/go/*": {"origins": "*"}})

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

SAFE_USER_FIELDS = [
    "id", "email", "full_name", "role", "referral_code", "referred_by",
    "youtube_link", "instagram_link", "tiktok_link", "follower_count",
    "total_earnings", "referral_earnings", "balance", "tier", "status",
    "onboarding_completed", "created_at", "admin_lock_timestamp"
]


def safe_json(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: safe_json(val) for key, val in value.items()}
    if isinstance(value, list):
        return [safe_json(item) for item in value]
    return value


def ok(payload: Optional[Dict[str, Any]] = None, status: int = 200):
    body = {"ok": True}
    if payload:
        body.update(payload)
    return jsonify(safe_json(body)), status


def error(message: str, status: int = 400, code: Optional[str] = None):
    body = {"ok": False, "error": message}
    if code:
        body["code"] = code
    return jsonify(body), status


def db_select_one(table: str, fields: str = "*", **filters) -> Optional[Dict[str, Any]]:
    query = supabase.table(table).select(fields)
    for key, value in filters.items():
        query = query.eq(key, value)
    response = query.limit(1).execute()
    rows = response.data or []
    return rows[0] if rows else None


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {field: user.get(field) for field in SAFE_USER_FIELDS if field in user}


def require_json() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {}
    return data


def make_token(user: Dict[str, Any]) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user.get("role", "normal_user"),
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(days=JWT_EXP_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def authenticate_request() -> Tuple[Optional[Dict[str, Any]], Optional[Any]]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, error("Missing authorization token.", 401, "AUTH_REQUIRED")

    token = auth_header.replace("Bearer ", "", 1).strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None, error("Session expired. Please login again.", 401, "TOKEN_EXPIRED")
    except jwt.InvalidTokenError:
        return None, error("Invalid authorization token.", 401, "INVALID_TOKEN")

    user = db_select_one("users", "*", id=payload.get("sub"))
    if not user:
        return None, error("User not found.", 401, "USER_NOT_FOUND")
    if user.get("status") == "banned":
        return None, error("Your account has been banned.", 403, "ACCOUNT_BANNED")

    return user, None


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user, auth_error = authenticate_request()
        if auth_error:
            return auth_error
        g.current_user = user
        return func(*args, **kwargs)
    return wrapper


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user, auth_error = authenticate_request()
        if auth_error:
            return auth_error
        if user.get("role") != "admin":
            return error("Admin access required.", 403, "ADMIN_REQUIRED")
        g.current_user = user
        return func(*args, **kwargs)
    return wrapper


def normalize_email(email: Any) -> str:
    return str(email or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def sanitize_role(role: Any) -> str:
    role = str(role or "normal_user").strip()
    return "influencer" if role == "influencer" else "normal_user"


def generate_referral_code(email: str) -> str:
    prefix = re.sub(r"[^A-Z0-9]", "", email.split("@")[0].upper())[:5] or "NEX"
    suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return f"{prefix}{suffix}"


def generate_short_code(user_id: str) -> str:
    random_part = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    user_suffix = str(user_id).replace("-", "").upper()[:6]
    return f"{random_part}-{user_suffix}"


def parse_amount(value: Any, field_name: str = "amount", allow_zero: bool = False) -> float:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f"{field_name} must be a valid number.")

    if allow_zero:
        if amount < 0:
            raise ValueError(f"{field_name} cannot be negative.")
    elif amount <= 0:
        raise ValueError(f"{field_name} must be greater than zero.")

    return float(amount.quantize(Decimal("0.01")))


def validate_uuid(value: Any, field_name: str = "id") -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} must be a valid UUID.")


def validate_http_url(value: Any, field_name: str) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"{field_name} must be a valid http or https URL.")
    return url


def validate_imgbb_url(value: Any) -> Optional[str]:
    if value is None or str(value).strip() == "":
        return None
    url = validate_http_url(value, "image_url")
    host = urlparse(url).netloc.lower()
    allowed = host in {"i.ibb.co", "ibb.co", "imgbb.com"} or host.endswith(".imgbb.com")
    if not allowed:
        raise ValueError("image_url must be an ImgBB URL.")
    return url


def normalize_text_list(value: Any, comma_split: bool = False) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    splitter = "," if comma_split else "\n"
    return [item.strip() for item in text.split(splitter) if item.strip()]


def normalize_product_payload(data: Dict[str, Any], partial: bool = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}

    required = ["title", "real_price", "sales_price", "commission_amount", "super_link"]
    if not partial:
        for field in required:
            if data.get(field) in (None, ""):
                raise ValueError(f"{field} is required.")

    if "title" in data:
        title = str(data.get("title") or "").strip()
        if not title:
            raise ValueError("title cannot be empty.")
        payload["title"] = title

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip() or None

    if "real_price" in data:
        payload["real_price"] = parse_amount(data.get("real_price"), "real_price", allow_zero=True)

    if "sales_price" in data:
        payload["sales_price"] = parse_amount(data.get("sales_price"), "sales_price", allow_zero=True)

    if "commission_amount" in data:
        payload["commission_amount"] = parse_amount(data.get("commission_amount"), "commission_amount", allow_zero=True)

    if "image_url" in data:
        payload["image_url"] = validate_imgbb_url(data.get("image_url"))

    if "super_link" in data:
        payload["super_link"] = validate_http_url(data.get("super_link"), "super_link")

    if "tags" in data:
        payload["tags"] = normalize_text_list(data.get("tags"), comma_split=True)

    if "category" in data:
        payload["category"] = str(data.get("category") or "").strip() or None

    if "stock_status" in data:
        stock_status = str(data.get("stock_status") or "active").strip()
        if stock_status not in {"active", "inactive"}:
            raise ValueError("stock_status must be active or inactive.")
        payload["stock_status"] = stock_status

    if "captions" in data:
        payload["captions"] = normalize_text_list(data.get("captions"))

    if "hashtags" in data:
        payload["hashtags"] = normalize_text_list(data.get("hashtags"), comma_split=True)

    if "scripts" in data:
        payload["scripts"] = normalize_text_list(data.get("scripts"))

    return payload


def rpc_data(response) -> Any:
    data = response.data
    if isinstance(data, list) and len(data) == 1:
        return data[0]
    return data


def db_error_to_response(exc: Exception):
    message = str(exc)
    known = {
        "EMAIL_EXISTS": ("Email is already registered.", 409),
        "INVALID_REFERRAL_CODE": ("Referral code is invalid.", 400),
        "INSUFFICIENT_BALANCE": ("Insufficient balance.", 400),
        "AMOUNT_BELOW_MINIMUM": ("Amount is below minimum withdrawal limit.", 400),
        "INVALID_AMOUNT": ("Invalid amount.", 400),
        "USER_NOT_FOUND": ("User not found.", 404),
        "PRODUCT_NOT_FOUND": ("Product not found.", 404),
        "WITHDRAWAL_NOT_FOUND": ("Withdrawal not found.", 404),
        "WITHDRAWAL_ALREADY_PROCESSED": ("Withdrawal has already been processed.", 400),
        "BANK_DETAILS_REQUIRED": ("Bank holder, account number, and IFSC are required.", 400),
        "UPI_DETAILS_REQUIRED": ("UPI ID is required.", 400),
        "DUPLICATE_COMMISSION_REFERENCE": ("Commission reference already exists.", 409),
    }
    for key, value in known.items():
        if key in message:
            return error(value[0], value[1], key)
    if "duplicate key" in message and "users_email" in message:
        return error("Email is already registered.", 409, "EMAIL_EXISTS")
    return error("Database request failed.", 500, "DATABASE_ERROR")


def create_user_via_rpc(email: str, password_hash: str, full_name: str, role: str, referral_code: Optional[str]) -> Dict[str, Any]:
    for _ in range(8):
        new_referral_code = generate_referral_code(email)
        try:
            response = supabase.rpc("register_user_atomic", {
                "p_email": email,
                "p_password_hash": password_hash,
                "p_full_name": full_name,
                "p_requested_role": sanitize_role(role),
                "p_new_referral_code": new_referral_code,
                "p_input_referral_code": referral_code or None
            }).execute()
            user = rpc_data(response)
            if not user:
                raise RuntimeError("User registration returned no data.")
            return user
        except Exception as exc:
            msg = str(exc)
            if "referral_code" in msg and "duplicate" in msg:
                continue
            raise
    raise RuntimeError("Could not generate a unique referral code.")


def notify_user(user_id: str, notification_type: str, message: str) -> None:
    try:
        supabase.table("notifications").insert({
            "user_id": user_id,
            "type": notification_type,
            "message": message
        }).execute()
    except Exception:
        app.logger.exception("Failed to create notification")


def notify_all_users(notification_type: str, message: str) -> None:
    try:
        users = supabase.table("users").select("id").eq("status", "active").execute().data or []
        payload = [{"user_id": user["id"], "type": notification_type, "message": message} for user in users]
        for index in range(0, len(payload), 500):
            chunk = payload[index:index + 500]
            if chunk:
                supabase.table("notifications").insert(chunk).execute()
    except Exception:
        app.logger.exception("Failed to create bulk notifications")


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def parse_datetime(value: Any) -> Optional[dt.datetime]:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def count_rows(table: str, filters: Optional[Dict[str, Any]] = None) -> int:
    query = supabase.table(table).select("id", count="exact")
    for key, value in (filters or {}).items():
        query = query.eq(key, value)
    response = query.execute()
    return int(response.count if response.count is not None else len(response.data or []))


def product_map(product_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    ids = list({pid for pid in product_ids if pid})
    if not ids:
        return {}
    products = supabase.table("products").select("id,title,image_url,category,sales_price,commission_amount").in_("id", ids).execute().data or []
    return {product["id"]: product for product in products}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    return ok({"service": "nexconnect", "domain": DOMAIN})


@app.route("/api/auth/admin-status")
def admin_status():
    lock = db_select_one("admin_lock", "*", id=1)
    admin_count = int((lock or {}).get("admin_count") or 0)
    return ok({
        "admin_count": admin_count,
        "locked": bool((lock or {}).get("locked_at") or admin_count >= 2),
        "locked_at": (lock or {}).get("locked_at")
    })


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = require_json()
    email = normalize_email(data.get("email"))
    password = str(data.get("password") or "")
    full_name = str(data.get("full_name") or "").strip()
    role = sanitize_role(data.get("role"))
    referral_code = str(data.get("referral_code") or "").strip().upper() or None

    if not is_valid_email(email):
        return error("A valid email is required.", 400)
    if len(password) < 8:
        return error("Password must be at least 8 characters.", 400)
    if not full_name:
        return error("Full name is required.", 400)

    password_hash = generate_password_hash(password)

    try:
        user = create_user_via_rpc(email, password_hash, full_name, role, referral_code)
        token = make_token(user)
        return ok({"token": token, "user": public_user(user)}, 201)
    except Exception as exc:
        return db_error_to_response(exc)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = require_json()
    email = normalize_email(data.get("email"))
    password = str(data.get("password") or "")

    if not is_valid_email(email) or not password:
        return error("Email and password are required.", 400)

    user = db_select_one("users", "*", email=email)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return error("Invalid email or password.", 401)
    if user.get("status") == "banned":
        return error("Your account has been banned.", 403)

    token = make_token(user)
    return ok({"token": token, "user": public_user(user)})


@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = require_json()
    email = normalize_email(data.get("email"))
    full_name = str(data.get("full_name") or "").strip()
    referral_code = str(data.get("referral_code") or "").strip().upper() or None

    if not is_valid_email(email):
        return error("A valid Google email is required.", 400)
    if not full_name:
        full_name = email.split("@")[0].replace(".", " ").title()

    existing = db_select_one("users", "*", email=email)
    if existing:
        if existing.get("status") == "banned":
            return error("Your account has been banned.", 403)
        return ok({"token": make_token(existing), "user": public_user(existing)})

    try:
        password_hash = generate_password_hash(secrets.token_urlsafe(32))
        user = create_user_via_rpc(email, password_hash, full_name, "normal_user", referral_code)
        return ok({"token": make_token(user), "user": public_user(user)}, 201)
    except Exception as exc:
        return db_error_to_response(exc)


@app.route("/api/auth/me")
@require_auth
def me():
    return ok({"user": public_user(g.current_user)})


@app.route("/api/users/profile", methods=["GET"])
@require_auth
def get_profile():
    return ok({"user": public_user(g.current_user)})


@app.route("/api/users/profile", methods=["PUT"])
@require_auth
def update_profile():
    data = require_json()
    user = g.current_user

    allowed = {
        "full_name", "youtube_link", "instagram_link", "tiktok_link",
        "follower_count", "onboarding_completed"
    }
    payload: Dict[str, Any] = {}

    for field in allowed:
        if field in data:
            payload[field] = data[field]

    if "follower_count" in payload:
        try:
            payload["follower_count"] = max(0, int(payload["follower_count"] or 0))
        except (TypeError, ValueError):
            return error("follower_count must be a number.", 400)

    if "role" in data and user.get("role") != "admin":
        payload["role"] = sanitize_role(data.get("role"))

    if not payload:
        return error("No profile fields provided.", 400)

    try:
        response = supabase.table("users").update(payload).eq("id", user["id"]).execute()
        updated = response.data[0] if response.data else db_select_one("users", "*", id=user["id"])
        return ok({"user": public_user(updated)})
    except Exception as exc:
        app.logger.exception("Profile update failed")
        return error("Profile update failed.", 500)


@app.route("/api/users/leaderboard")
@require_auth
def leaderboard():
    period = request.args.get("period", "week")
    now = dt.datetime.now(dt.timezone.utc)

    if period == "month":
        since = now - dt.timedelta(days=30)
    elif period == "all":
        since = None
    else:
        period = "week"
        since = now - dt.timedelta(days=7)

    try:
        if since:
            events = supabase.table("commission_events").select("user_id,amount,created_at").gte("created_at", since.isoformat()).execute().data or []
            earnings: Dict[str, float] = {}
            for event in events:
                earnings[event["user_id"]] = earnings.get(event["user_id"], 0.0) + float(event.get("amount") or 0)
            users_by_id = {}
            if earnings:
                users = supabase.table("users").select(",".join(SAFE_USER_FIELDS)).in_("id", list(earnings.keys())).execute().data or []
                users_by_id = {user["id"]: user for user in users}
            rows = []
            for user_id, amount in earnings.items():
                user = users_by_id.get(user_id)
                if user and user.get("status") == "active":
                    row = public_user(user)
                    row["earnings"] = round(amount, 2)
                    rows.append(row)
        else:
            users = supabase.table("users").select(",".join(SAFE_USER_FIELDS)).eq("status", "active").execute().data or []
            rows = []
            for user in users:
                row = public_user(user)
                row["earnings"] = float(user.get("total_earnings") or 0) + float(user.get("referral_earnings") or 0)
                rows.append(row)

        rows.sort(key=lambda item: item.get("earnings", 0), reverse=True)
        return ok({"period": period, "leaderboard": rows[:25]})
    except Exception:
        app.logger.exception("Leaderboard failed")
        return error("Could not load leaderboard.", 500)


@app.route("/api/products")
@require_auth
def list_products():
    category = request.args.get("category")
    search = str(request.args.get("search") or "").strip().lower()
    tag = str(request.args.get("tag") or "").strip()
    min_price = request.args.get("min_price")
    max_price = request.args.get("max_price")

    try:
        query = supabase.table("products").select("*").eq("stock_status", "active")

        if category:
            query = query.eq("category", category)
        if min_price:
            query = query.gte("sales_price", parse_amount(min_price, "min_price", allow_zero=True))
        if max_price:
            query = query.lte("sales_price", parse_amount(max_price, "max_price", allow_zero=True))

        products = query.order("created_at", desc=True).limit(500).execute().data or []

        if tag:
            products = [p for p in products if tag in (p.get("tags") or [])]

        if search:
            products = [
                p for p in products
                if search in f"{p.get('title') or ''} {p.get('description') or ''} {p.get('category') or ''} {' '.join(p.get('tags') or [])}".lower()
            ]

        return ok({"products": products})
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception:
        app.logger.exception("Product list failed")
        return error("Could not load products.", 500)


@app.route("/api/products/<product_id>")
@require_auth
def product_detail(product_id):
    try:
        validate_uuid(product_id, "product_id")
        product = db_select_one("products", "*", id=product_id)
        if not product or product.get("stock_status") != "active":
            return error("Product not found.", 404)
        return ok({"product": product})
    except ValueError as exc:
        return error(str(exc), 400)


@app.route("/api/products/<product_id>/similar")
@require_auth
def similar_products(product_id):
    try:
        validate_uuid(product_id, "product_id")
        product = db_select_one("products", "*", id=product_id)
        if not product or product.get("stock_status") != "active":
            return error("Product not found.", 404)

        query = supabase.table("products").select("*").eq("stock_status", "active")
        if product.get("category"):
            query = query.eq("category", product["category"])
        products = query.limit(100).execute().data or []

        product_tags = set(product.get("tags") or [])
        filtered = [p for p in products if p["id"] != product_id]
        filtered.sort(key=lambda p: len(product_tags.intersection(set(p.get("tags") or []))), reverse=True)

        return ok({"products": filtered[:8]})
    except ValueError as exc:
        return error(str(exc), 400)


@app.route("/api/links/generate", methods=["POST"])
@require_auth
def generate_link():
    data = require_json()
    user = g.current_user

    try:
        product_id = validate_uuid(data.get("product_id"), "product_id")
    except ValueError as exc:
        return error(str(exc), 400)

    product = db_select_one("products", "*", id=product_id)
    if not product or product.get("stock_status") != "active":
        return error("Product not found.", 404)

    existing = db_select_one("short_links", "*", user_id=user["id"], product_id=product_id)
    if existing:
        return ok({
            "short_code": existing["short_code"],
            "short_url": f"{BASE_URL}/go/{existing['short_code']}"
        })

    for _ in range(10):
        short_code = generate_short_code(user["id"])
        try:
            response = supabase.table("short_links").insert({
                "user_id": user["id"],
                "product_id": product_id,
                "short_code": short_code
            }).execute()
            link = response.data[0]
            return ok({"short_code": link["short_code"], "short_url": f"{BASE_URL}/go/{link['short_code']}"}, 201)
        except Exception as exc:
            if "duplicate" in str(exc).lower():
                continue
            app.logger.exception("Short link insert failed")
            return error("Could not generate short link.", 500)

    return error("Could not generate unique short link.", 500)


@app.route("/go/<path:short_code>")
def open_short_link(short_code):
    code = str(short_code or "").strip().upper()
    link = db_select_one("short_links", "*", short_code=code)
    if not link:
        return "NexConnect link not found.", 404

    product = db_select_one("products", "*", id=link["product_id"])
    if not product or not product.get("super_link"):
        return "NexConnect product destination not found.", 404

    try:
        supabase.table("clicks").insert({
            "user_id": link["user_id"],
            "product_id": link["product_id"],
            "short_code": code,
            "ip_address": get_client_ip()
        }).execute()
    except Exception:
        app.logger.exception("Click logging failed")

    return redirect(product["super_link"], code=302)


@app.route("/api/clicks")
@require_auth
def click_history():
    user = g.current_user
    rows = supabase.table("clicks").select("*").eq("user_id", user["id"]).order("created_at", desc=True).limit(100).execute().data or []
    products = product_map([row.get("product_id") for row in rows])
    for row in rows:
        product = products.get(row.get("product_id")) or {}
        row["product_title"] = product.get("title")
        row["product"] = product
    return ok({"clicks": rows})


@app.route("/api/clicks/stats")
@require_auth
def click_stats():
    user = g.current_user
    period = request.args.get("period", "week")
    days = 30 if period == "month" else 7
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)

    total_clicks = count_rows("clicks", {"user_id": user["id"]})

    period_clicks = supabase.table("clicks").select("*").eq("user_id", user["id"]).gte("created_at", since.isoformat()).order("created_at", desc=False).limit(5000).execute().data or []
    recent_clicks = supabase.table("clicks").select("*").eq("user_id", user["id"]).order("created_at", desc=True).limit(10).execute().data or []

    products = product_map([row.get("product_id") for row in recent_clicks + period_clicks])
    for row in recent_clicks:
        row["product_title"] = (products.get(row.get("product_id")) or {}).get("title")

    date_labels: List[str] = []
    date_counts: Dict[str, int] = {}

    for offset in range(days - 1, -1, -1):
        date_value = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=offset)).date()
        key = date_value.isoformat()
        date_labels.append(date_value.strftime("%d %b"))
        date_counts[key] = 0

    for click in period_clicks:
        parsed = parse_datetime(click.get("created_at"))
        if parsed:
            key = parsed.date().isoformat()
            if key in date_counts:
                date_counts[key] += 1

    product_counts: Dict[str, int] = {}
    for click in period_clicks:
        pid = click.get("product_id")
        if pid:
            product_counts[pid] = product_counts.get(pid, 0) + 1

    top_product = None
    if product_counts:
        top_id = max(product_counts, key=product_counts.get)
        product = products.get(top_id) or db_select_one("products", "id,title,image_url,category", id=top_id)
        if product:
            top_product = {
                "id": top_id,
                "title": product.get("title"),
                "clicks": product_counts[top_id]
            }

    commissions = supabase.table("commission_events").select("id").eq("user_id", user["id"]).execute().data or []
    conversion_rate = round((len(commissions) / total_clicks) * 100, 2) if total_clicks else 0

    stats = {
        "total_clicks": total_clicks,
        "total_earnings": float(user.get("total_earnings") or 0),
        "referral_earnings": float(user.get("referral_earnings") or 0),
        "balance": float(user.get("balance") or 0),
        "conversion_rate": conversion_rate,
        "top_product": top_product,
        "recent_clicks": recent_clicks,
        "chart": {
            "labels": date_labels,
            "values": list(date_counts.values())
        }
    }

    return ok({"stats": stats})


@app.route("/api/withdrawals", methods=["POST"])
@require_auth
def create_withdrawal():
    data = require_json()
    user = g.current_user

    try:
        amount = parse_amount(data.get("amount"))
        method = str(data.get("method") or "").strip()
        if method not in {"bank", "upi"}:
            return error("method must be bank or upi.", 400)

        response = supabase.rpc("create_withdrawal_request_atomic", {
            "p_user_id": user["id"],
            "p_amount": amount,
            "p_method": method,
            "p_bank_ifsc": str(data.get("bank_ifsc") or "").strip() or None,
            "p_bank_account": str(data.get("bank_account") or "").strip() or None,
            "p_bank_holder": str(data.get("bank_holder") or "").strip() or None,
            "p_upi_id": str(data.get("upi_id") or "").strip() or None,
        }).execute()
        return ok({"withdrawal": rpc_data(response)}, 201)
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception as exc:
        return db_error_to_response(exc)


@app.route("/api/withdrawals")
@require_auth
def withdrawal_history():
    rows = supabase.table("withdrawals").select("*").eq("user_id", g.current_user["id"]).order("created_at", desc=True).execute().data or []
    return ok({"withdrawals": rows})


@app.route("/api/referrals")
@require_auth
def referrals():
    user = g.current_user
    referred = supabase.table("users").select(",".join(SAFE_USER_FIELDS)).eq("referred_by", user["id"]).order("created_at", desc=True).execute().data or []
    earnings = supabase.table("referral_earnings").select("*").eq("referrer_id", user["id"]).order("created_at", desc=True).execute().data or []
    total = sum(float(row.get("amount") or 0) for row in earnings)

    return ok({
        "referral_code": user.get("referral_code"),
        "referral_link": f"{BASE_URL}/#/signup?ref={user.get('referral_code')}",
        "referrals": [public_user(row) for row in referred],
        "earnings": earnings,
        "summary": {
            "total_referrals": len(referred),
            "total_referral_earnings": round(total, 2)
        }
    })


@app.route("/api/referrals/stats")
@require_auth
def referral_stats():
    user = g.current_user
    total_referrals = count_rows("users", {"referred_by": user["id"]})
    return ok({
        "stats": {
            "total_referrals": total_referrals,
            "total_referral_earnings": float(user.get("referral_earnings") or 0),
            "referral_code": user.get("referral_code"),
            "referral_link": f"{BASE_URL}/#/signup?ref={user.get('referral_code')}"
        }
    })


@app.route("/api/bookmarks", methods=["POST"])
@require_auth
def add_bookmark():
    data = require_json()
    try:
        product_id = validate_uuid(data.get("product_id"), "product_id")
    except ValueError as exc:
        return error(str(exc), 400)

    product = db_select_one("products", "*", id=product_id)
    if not product or product.get("stock_status") != "active":
        return error("Product not found.", 404)

    existing = db_select_one("bookmarks", "*", user_id=g.current_user["id"], product_id=product_id)
    if existing:
        existing["product"] = product
        return ok({"bookmark": existing})

    try:
        response = supabase.table("bookmarks").insert({
            "user_id": g.current_user["id"],
            "product_id": product_id
        }).execute()
        bookmark = response.data[0]
        bookmark["product"] = product
        return ok({"bookmark": bookmark}, 201)
    except Exception:
        app.logger.exception("Bookmark insert failed")
        return error("Could not save bookmark.", 500)


@app.route("/api/bookmarks")
@require_auth
def list_bookmarks():
    rows = supabase.table("bookmarks").select("*").eq("user_id", g.current_user["id"]).order("created_at", desc=True).execute().data or []
    products = product_map([row.get("product_id") for row in rows])
    for row in rows:
        row["product"] = products.get(row.get("product_id"))
    return ok({"bookmarks": rows})


@app.route("/api/bookmarks/<bookmark_or_product_id>", methods=["DELETE"])
@require_auth
def remove_bookmark(bookmark_or_product_id):
    user_id = g.current_user["id"]

    try:
        response = supabase.table("bookmarks").delete().eq("id", bookmark_or_product_id).eq("user_id", user_id).execute()
        if not response.data:
            supabase.table("bookmarks").delete().eq("product_id", bookmark_or_product_id).eq("user_id", user_id).execute()
        return ok({"deleted": True})
    except Exception:
        app.logger.exception("Bookmark delete failed")
        return error("Could not remove bookmark.", 500)


@app.route("/api/support", methods=["POST"])
@require_auth
def send_support_message():
    data = require_json()
    message = str(data.get("message") or "").strip()
    if not message:
        return error("Message is required.", 400)
    if len(message) > 2000:
        return error("Message cannot exceed 2000 characters.", 400)

    response = supabase.table("support_messages").insert({
        "user_id": g.current_user["id"],
        "message": message
    }).execute()

    admins = supabase.table("users").select("id").eq("role", "admin").eq("status", "active").execute().data or []
    for admin in admins:
        notify_user(admin["id"], "support", "New support message received.")

    return ok({"message": response.data[0]}, 201)


@app.route("/api/support")
@require_auth
def support_history():
    rows = supabase.table("support_messages").select("*").eq("user_id", g.current_user["id"]).order("created_at", desc=True).execute().data or []
    return ok({"messages": rows})


@app.route("/api/notifications")
@require_auth
def notifications():
    rows = supabase.table("notifications").select("*").eq("user_id", g.current_user["id"]).order("created_at", desc=True).limit(50).execute().data or []
    unread_count = len([row for row in rows if not row.get("is_read")])
    return ok({"notifications": rows, "unread_count": unread_count})


@app.route("/api/notifications/<notification_id>/read", methods=["PUT"])
@require_auth
def read_notification(notification_id):
    try:
        validate_uuid(notification_id, "notification_id")
        supabase.table("notifications").update({"is_read": True}).eq("id", notification_id).eq("user_id", g.current_user["id"]).execute()
        return ok({"updated": True})
    except ValueError as exc:
        return error(str(exc), 400)


@app.route("/api/settings")
def public_settings():
    settings = db_select_one("settings", "*", id=1) or {}
    defaults = {
        "id": 1,
        "hero_banner_url": None,
        "hero_title": "Connect. Create. Earn.",
        "hero_subtitle": "Share curated products, track clicks, grow referrals, and withdraw earnings from NexConnect.",
        "min_withdrawal": 100.00,
        "support_email": "support@nexconnect.com",
        "terms_content": "",
        "privacy_content": ""
    }
    defaults.update(settings)
    return ok({"settings": defaults})


@app.route("/api/admin/products", methods=["GET"])
@require_admin
def admin_products():
    status = request.args.get("stock_status")
    query = supabase.table("products").select("*")
    if status in {"active", "inactive"}:
        query = query.eq("stock_status", status)
    rows = query.order("created_at", desc=True).limit(1000).execute().data or []
    return ok({"products": rows})


@app.route("/api/admin/products", methods=["POST"])
@require_admin
def admin_create_product():
    try:
        payload = normalize_product_payload(require_json(), partial=False)
        response = supabase.table("products").insert(payload).execute()
        product = response.data[0]
        notify_all_users("new_product", f"New product available: {product['title']}")
        return ok({"product": product}, 201)
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception:
        app.logger.exception("Admin product create failed")
        return error("Could not create product.", 500)


@app.route("/api/admin/products/<product_id>", methods=["PUT"])
@require_admin
def admin_update_product(product_id):
    try:
        validate_uuid(product_id, "product_id")
        payload = normalize_product_payload(require_json(), partial=True)
        if not payload:
            return error("No product fields provided.", 400)
        response = supabase.table("products").update(payload).eq("id", product_id).execute()
        product = response.data[0] if response.data else db_select_one("products", "*", id=product_id)
        return ok({"product": product})
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception:
        app.logger.exception("Admin product update failed")
        return error("Could not update product.", 500)


@app.route("/api/admin/products/<product_id>", methods=["DELETE"])
@require_admin
def admin_delete_product(product_id):
    try:
        validate_uuid(product_id, "product_id")
        response = supabase.table("products").update({"stock_status": "inactive"}).eq("id", product_id).execute()
        product = response.data[0] if response.data else db_select_one("products", "*", id=product_id)
        return ok({"product": product, "deleted": True})
    except ValueError as exc:
        return error(str(exc), 400)


@app.route("/api/admin/users")
@require_admin
def admin_users():
    role = request.args.get("role")
    status = request.args.get("status")
    search = str(request.args.get("search") or "").strip().lower()

    query = supabase.table("users").select(",".join(SAFE_USER_FIELDS))
    if role in {"admin", "influencer", "normal_user"}:
        query = query.eq("role", role)
    if status in {"active", "banned"}:
        query = query.eq("status", status)

    rows = query.order("created_at", desc=True).limit(1000).execute().data or []
    if search:
        rows = [
            row for row in rows
            if search in f"{row.get('email') or ''} {row.get('full_name') or ''} {row.get('referral_code') or ''}".lower()
        ]
    return ok({"users": rows})


@app.route("/api/admin/users/<user_id>", methods=["PUT"])
@require_admin
def admin_update_user(user_id):
    try:
        validate_uuid(user_id, "user_id")
    except ValueError as exc:
        return error(str(exc), 400)

    target = db_select_one("users", "*", id=user_id)
    if not target:
        return error("User not found.", 404)

    data = require_json()
    allowed = {
        "full_name", "youtube_link", "instagram_link", "tiktok_link",
        "follower_count", "status", "tier", "balance", "total_earnings",
        "referral_earnings", "onboarding_completed"
    }
    payload = {field: data[field] for field in allowed if field in data}

    if "role" in data:
        new_role = str(data.get("role"))
        if new_role == "admin" and target.get("role") != "admin":
            return error("Admin role cannot be assigned after the first two automatic admins.", 403)
        if new_role in {"normal_user", "influencer"} and target.get("role") != "admin":
            payload["role"] = new_role

    if "status" in payload and payload["status"] not in {"active", "banned"}:
        return error("status must be active or banned.", 400)
    if "tier" in payload and payload["tier"] not in {"bronze", "silver", "gold"}:
        return error("tier must be bronze, silver, or gold.", 400)

    for money_field in ["balance", "total_earnings", "referral_earnings"]:
        if money_field in payload:
            try:
                payload[money_field] = parse_amount(payload[money_field], money_field, allow_zero=True)
            except ValueError as exc:
                return error(str(exc), 400)

    if "follower_count" in payload:
        try:
            payload["follower_count"] = max(0, int(payload["follower_count"] or 0))
        except (TypeError, ValueError):
            return error("follower_count must be a number.", 400)

    if not payload:
        return error("No user fields provided.", 400)

    response = supabase.table("users").update(payload).eq("id", user_id).execute()
    updated = response.data[0] if response.data else db_select_one("users", ",".join(SAFE_USER_FIELDS), id=user_id)
    return ok({"user": public_user(updated)})


@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
@require_admin
def admin_delete_user(user_id):
    try:
        validate_uuid(user_id, "user_id")
        response = supabase.table("users").update({"status": "banned"}).eq("id", user_id).execute()
        updated = response.data[0] if response.data else db_select_one("users", ",".join(SAFE_USER_FIELDS), id=user_id)
        return ok({"user": public_user(updated), "deleted": True})
    except ValueError as exc:
        return error(str(exc), 400)


@app.route("/api/admin/withdrawals")
@require_admin
def admin_withdrawals():
    status = request.args.get("status")
    query = supabase.table("withdrawals").select("*")
    if status in {"pending", "approved", "rejected"}:
        query = query.eq("status", status)
    rows = query.order("created_at", desc=True).limit(1000).execute().data or []
    return ok({"withdrawals": rows})


@app.route("/api/admin/withdrawals/<withdrawal_id>", methods=["PUT"])
@require_admin
def admin_process_withdrawal(withdrawal_id):
    data = require_json()
    try:
        validate_uuid(withdrawal_id, "withdrawal_id")
        status = str(data.get("status") or "").strip()
        if status not in {"approved", "rejected"}:
            return error("status must be approved or rejected.", 400)

        response = supabase.rpc("process_withdrawal_atomic", {
            "p_withdrawal_id": withdrawal_id,
            "p_status": status,
            "p_reason": str(data.get("reason") or "").strip() or None
        }).execute()
        return ok({"withdrawal": rpc_data(response)})
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception as exc:
        return db_error_to_response(exc)


@app.route("/api/admin/support")
@require_admin
def admin_support_messages():
    rows = supabase.table("support_messages").select("*").order("created_at", desc=True).limit(1000).execute().data or []
    users = product_map([])
    user_ids = list({row["user_id"] for row in rows if row.get("user_id")})
    users_by_id = {}
    if user_ids:
        user_rows = supabase.table("users").select("id,email,full_name").in_("id", user_ids).execute().data or []
        users_by_id = {user["id"]: user for user in user_rows}

    for row in rows:
        row["user"] = users_by_id.get(row.get("user_id"))
    return ok({"messages": rows})


@app.route("/api/admin/support/<message_id>/reply", methods=["PUT"])
@require_admin
def admin_reply_support(message_id):
    data = require_json()
    reply = str(data.get("reply") or "").strip()
    if not reply:
        return error("Reply is required.", 400)

    try:
        validate_uuid(message_id, "message_id")
    except ValueError as exc:
        return error(str(exc), 400)

    message = db_select_one("support_messages", "*", id=message_id)
    if not message:
        return error("Support message not found.", 404)

    response = supabase.table("support_messages").update({
        "reply": reply,
        "replied_at": dt.datetime.now(dt.timezone.utc).isoformat()
    }).eq("id", message_id).execute()

    notify_user(message["user_id"], "support", "Your support message has a new admin reply.")
    return ok({"message": response.data[0] if response.data else db_select_one("support_messages", "*", id=message_id)})


@app.route("/api/admin/settings", methods=["GET"])
@require_admin
def admin_get_settings():
    return public_settings()


@app.route("/api/admin/settings", methods=["PUT"])
@require_admin
def admin_update_settings():
    data = require_json()
    payload: Dict[str, Any] = {"id": 1}

    if "hero_banner_url" in data:
        payload["hero_banner_url"] = validate_imgbb_url(data.get("hero_banner_url"))
    for field in ["hero_title", "hero_subtitle", "support_email", "terms_content", "privacy_content"]:
        if field in data:
            payload[field] = str(data.get(field) or "").strip() or None
    if "min_withdrawal" in data:
        try:
            payload["min_withdrawal"] = parse_amount(data.get("min_withdrawal"), "min_withdrawal")
        except ValueError as exc:
            return error(str(exc), 400)

    payload["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    try:
        response = supabase.table("settings").upsert(payload, on_conflict="id").execute()
        return ok({"settings": response.data[0] if response.data else db_select_one("settings", "*", id=1)})
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception:
        app.logger.exception("Settings update failed")
        return error("Could not update settings.", 500)


@app.route("/api/admin/analytics")
@require_admin
def admin_analytics():
    users = supabase.table("users").select("id,role,status,total_earnings,referral_earnings,balance").execute().data or []
    total_balance = sum(float(user.get("balance") or 0) for user in users)
    total_earnings = sum(float(user.get("total_earnings") or 0) + float(user.get("referral_earnings") or 0) for user in users)

    return ok({
        "analytics": {
            "users": len(users),
            "admins": len([user for user in users if user.get("role") == "admin"]),
            "creators": len([user for user in users if user.get("role") == "influencer"]),
            "active_users": len([user for user in users if user.get("status") == "active"]),
            "products": count_rows("products"),
            "active_products": count_rows("products", {"stock_status": "active"}),
            "clicks": count_rows("clicks"),
            "pending_withdrawals": count_rows("withdrawals", {"status": "pending"}),
            "total_platform_balance": round(total_balance, 2),
            "total_user_earnings": round(total_earnings, 2)
        }
    })


@app.route("/api/admin/commissions", methods=["POST"])
@require_admin
def admin_credit_commission():
    data = require_json()
    try:
        user_id = validate_uuid(data.get("user_id"), "user_id")
        product_id = validate_uuid(data.get("product_id"), "product_id")
        amount = parse_amount(data.get("amount"))
        response = supabase.rpc("credit_commission_atomic", {
            "p_user_id": user_id,
            "p_product_id": product_id,
            "p_amount": amount,
            "p_external_reference": str(data.get("external_reference") or "").strip() or None,
            "p_notes": str(data.get("notes") or "").strip() or None
        }).execute()
        return ok({"commission": rpc_data(response)}, 201)
    except ValueError as exc:
        return error(str(exc), 400)
    except Exception as exc:
        return db_error_to_response(exc)


@app.route("/api/admin/notifications", methods=["POST"])
@require_admin
def admin_send_notification():
    data = require_json()
    message = str(data.get("message") or "").strip()
    notification_type = str(data.get("type") or "announcement").strip() or "announcement"
    user_id = str(data.get("user_id") or "").strip()

    if not message:
        return error("message is required.", 400)

    if user_id:
        try:
            validate_uuid(user_id, "user_id")
        except ValueError as exc:
            return error(str(exc), 400)
        notify_user(user_id, notification_type, message)
    else:
        notify_all_users(notification_type, message)

    return ok({"sent": True}, 201)


@app.route("/<path:path>")
def spa_fallback(path):
    if path.startswith("api/") or path.startswith("go/") or path == "admin":
        return error("Not found.", 404)
    return render_template("index.html")


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return error("Not found.", 404)
    return render_template("index.html")


@app.errorhandler(500)
def server_error(exc):
    app.logger.exception("Unhandled server error: %s", exc)
    if request.path.startswith("/api/"):
        return error("Internal server error.", 500)
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
