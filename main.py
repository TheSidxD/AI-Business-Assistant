import os
import sqlite3
import re
import html
import time
import hmac
import hashlib
import json
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel
from google import genai

# =========================================================
# CONFIG
# =========================================================

load_dotenv()

DB_NAME = "business.db"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-3.6-flash"

gemini_client = None

if GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        print("Gemini API: configured")
    except Exception as e:
        print("Gemini client error:", e)
else:
    print("Gemini API: no API key found")


# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI(
    title="AI Business Assistant"
)

# Project folder
BASE_DIR = Path(__file__).resolve().parent

# Static folder
STATIC_DIR = BASE_DIR / "static"

# Create static folder automatically if missing
STATIC_DIR.mkdir(
    parents=True,
    exist_ok=True
)

# Serve /static/*
app.mount(
    "/static",
    StaticFiles(
        directory=str(STATIC_DIR)
    ),
    name="static"
)

# =========================================================
# ADMIN SECURITY
# =========================================================

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")

ADMIN_COOKIE = "admin_auth"
ADMIN_SESSION_SECONDS = 60 * 60 * 24 * 7  # 7 days


def create_admin_token():
    timestamp = str(int(time.time()))

    signature = hmac.new(
        ADMIN_SECRET.encode("utf-8"),
        timestamp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{timestamp}.{signature}"


def verify_admin_token(token):
    if not token or "." not in token:
        return False

    timestamp, signature = token.split(".", 1)

    try:
        timestamp_int = int(timestamp)
    except ValueError:
        return False

    # Session expired
    if time.time() - timestamp_int > ADMIN_SESSION_SECONDS:
        return False

    expected_signature = hmac.new(
        ADMIN_SECRET.encode("utf-8"),
        timestamp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        signature,
        expected_signature
    )


@app.middleware("http")
async def admin_protection(request: Request, call_next):

    path = request.url.path

    # Public routes
    public_admin_routes = {
        "/admin/login",
        "/admin/logout"
    }

    # Only protect /admin/*
    if (
        path.startswith("/admin")
        and path not in public_admin_routes
    ):

        token = request.cookies.get(ADMIN_COOKIE)

        if not verify_admin_token(token):
            return RedirectResponse(
                "/admin/login",
                status_code=303
            )

    return await call_next(request)


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():

    return """
    <!DOCTYPE html>
    <html>
    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>Admin Login</title>

        <style>

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                min-height: 100vh;

                display: flex;
                align-items: center;
                justify-content: center;

                font-family:
                    Inter,
                    -apple-system,
                    BlinkMacSystemFont,
                    "Segoe UI",
                    sans-serif;

                color: white;

                background:
                    radial-gradient(
                        circle at 20% 10%,
                        rgba(79,124,255,.25),
                        transparent 30%
                    ),
                    radial-gradient(
                        circle at 80% 90%,
                        rgba(118,76,255,.20),
                        transparent 30%
                    ),
                    #050816;

                padding: 20px;
            }

            .login-box {
                width: 100%;
                max-width: 420px;

                padding: 32px;

                border-radius: 25px;

                background:
                    rgba(255,255,255,.06);

                border:
                    1px solid rgba(255,255,255,.12);

                backdrop-filter:
                    blur(30px);

                box-shadow:
                    0 25px 80px rgba(0,0,0,.40);
            }

            .logo {
                width: 58px;
                height: 58px;

                display: flex;
                align-items: center;
                justify-content: center;

                border-radius: 17px;

                background:
                    linear-gradient(
                        135deg,
                        #4f7cff,
                        #764cff
                    );

                font-size: 25px;

                margin-bottom: 20px;
            }

            h1 {
                margin: 0 0 8px;
                font-size: 27px;
            }

            .subtitle {
                margin-bottom: 28px;
                color: #94a3b8;
                font-size: 13px;
            }

            label {
                display: block;

                margin-bottom: 8px;

                color: #94a3b8;
                font-size: 12px;
            }

            input {
                width: 100%;

                padding: 14px;

                margin-bottom: 18px;

                border-radius: 14px;

                border:
                    1px solid rgba(255,255,255,.10);

                background:
                    rgba(255,255,255,.05);

                color: white;

                outline: none;
            }

            input:focus {
                border-color: #4f7cff;
            }

            button {
                width: 100%;

                padding: 14px;

                border: 0;

                border-radius: 14px;

                color: white;

                font-size: 14px;
                font-weight: 700;

                cursor: pointer;

                background:
                    linear-gradient(
                        135deg,
                        #4f7cff,
                        #764cff
                    );
            }

            button:hover {
                filter: brightness(1.1);
            }

        </style>

    </head>

    <body>

        <div class="login-box">

            <div class="logo">
                ✦
            </div>

            <h1>
                Admin Login
            </h1>

            <div class="subtitle">
                Sign in to manage your AI Business Assistant.
            </div>

            <form
                method="post"
                action="/admin/login"
            >

                <label>
                    Username
                </label>

                <input
                    type="text"
                    name="username"
                    placeholder="Admin username"
                    required
                >

                <label>
                    Password
                </label>

                <input
                    type="password"
                    name="password"
                    placeholder="Admin password"
                    required
                >

                <button type="submit">
                    🔐 Sign In
                </button>

            </form>

        </div>

    </body>
    </html>
    """


@app.post("/admin/login")
def admin_login(
    username: str = Form(...),
    password: str = Form(...)
):

    if (
        not ADMIN_USERNAME
        or not ADMIN_PASSWORD
        or not ADMIN_SECRET
    ):
        return HTMLResponse(
            """
            <h2 style="font-family:Arial;text-align:center;margin-top:100px;">
                Admin login is not configured.
            </h2>

            <p style="font-family:Arial;text-align:center;">
                Add ADMIN_USERNAME, ADMIN_PASSWORD and ADMIN_SECRET
                to your .env file.
            </p>
            """,
            status_code=500
        )

    username_ok = hmac.compare_digest(
        username,
        ADMIN_USERNAME
    )

    password_ok = hmac.compare_digest(
        password,
        ADMIN_PASSWORD
    )

    if not (username_ok and password_ok):

        return HTMLResponse(
            """
            <div style="
                max-width:420px;
                margin:100px auto;
                text-align:center;
                font-family:Arial;
            ">

                <h2>
                    ❌ Invalid username or password
                </h2>

                <a href="/admin/login">
                    Try Again
                </a>

            </div>
            """,
            status_code=401
        )

    response = RedirectResponse(
        "/admin",
        status_code=303
    )

    response.set_cookie(
        key=ADMIN_COOKIE,
        value=create_admin_token(),
        max_age=ADMIN_SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False
    )

    return response


@app.get("/admin/logout")
def admin_logout():

    response = RedirectResponse(
        "/admin/login",
        status_code=303
    )

    response.delete_cookie(
        ADMIN_COOKIE
    )

    return response


# =========================================================
# DATABASE
# =========================================================

def get_db():
    return sqlite3.connect(DB_NAME)


def clean_price(price):
    if price is None:
        return ""

    price = str(price).strip()

    # Remove existing currency symbols and commas
    price = price.replace("₹", "")
    price = price.replace("INR", "")
    price = price.replace("inr", "")
    price = price.replace(",", "")
    
    return price.strip()


def clean_existing_prices():
    db = get_db()

    products = db.execute(
        "SELECT id, price FROM products"
    ).fetchall()

    for product_id, price in products:
        cleaned = clean_price(price)

        db.execute(
            "UPDATE products SET price = ? WHERE id = ?",
            (cleaned, product_id)
        )

    orders = db.execute(
        "SELECT id, price FROM orders"
    ).fetchall()

    for order_id, price in orders:
        cleaned = clean_price(price)

        db.execute(
            "UPDATE orders SET price = ? WHERE id = ?",
            (cleaned, order_id)
        )

    db.commit()
    db.close()


def assign_product_categories():
    db = get_db()

    products = db.execute("""
        SELECT id, name
        FROM products
    """).fetchall()

    for product_id, name in products:

        name_lower = (name or "").lower()

        # =====================================================
        # ELECTRONICS
        # =====================================================

        if any(x in name_lower for x in [
            "iphone", "ipad", "samsung", "oneplus",
            "pixel", "redmi", "realme", "vivo", "oppo",
            "phone", "mobile", "smartphone"
        ]):
            category = "Electronics"
            subcategory = "Smartphones"

        elif any(x in name_lower for x in [
            "laptop", "macbook", "notebook pc",
            "chromebook", "thinkpad", "ideapad"
        ]):
            category = "Electronics"
            subcategory = "Laptops"

        elif any(x in name_lower for x in [
            "tablet", "ipad"
        ]):
            category = "Electronics"
            subcategory = "Tablets"

        elif any(x in name_lower for x in [
            "tv", "television", "oled", "qled"
        ]):
            category = "Electronics"
            subcategory = "Televisions"

        elif any(x in name_lower for x in [
            "airpods", "earbuds", "headphone",
            "headphones", "speaker", "soundbar",
            "earphone"
        ]):
            category = "Electronics"
            subcategory = "Audio"

        elif any(x in name_lower for x in [
            "watch", "smartwatch"
        ]):
            category = "Electronics"
            subcategory = "Smart Watches"

        elif any(x in name_lower for x in [
            "camera", "dslr", "gopro"
        ]):
            category = "Electronics"
            subcategory = "Cameras"

        elif any(x in name_lower for x in [
            "playstation", "ps5", "ps4",
            "xbox", "nintendo"
        ]):
            category = "Electronics"
            subcategory = "Gaming"

        # =====================================================
        # CLOTHING
        # =====================================================

        elif any(x in name_lower for x in [
            "shirt", "t-shirt", "jeans",
            "dress", "hoodie", "jacket",
            "kurta", "saree", "clothing"
        ]):
            category = "Clothing"

            if any(x in name_lower for x in [
                "men", "mens", "man", "shirt"
            ]):
                subcategory = "Men"

            elif any(x in name_lower for x in [
                "women", "womens", "woman",
                "dress", "saree"
            ]):
                subcategory = "Women"

            elif any(x in name_lower for x in [
                "kid", "kids", "children"
            ]):
                subcategory = "Kids"

            else:
                subcategory = "Men"

        # =====================================================
        # KIDS
        # =====================================================

        elif any(x in name_lower for x in [
            "kid", "kids", "children", "baby"
        ]):
            category = "Kids"
            subcategory = "Kids"

        elif "toy" in name_lower:
            category = "Kids"
            subcategory = "Toys"

        # =====================================================
        # STATIONERY
        # =====================================================

        elif any(x in name_lower for x in [
            "pen", "pencil", "notebook",
            "notepad", "stationery", "marker",
            "eraser"
        ]):
            category = "Stationery"
            subcategory = "Stationery"

        # =====================================================
        # FOOTWEAR
        # =====================================================

        elif any(x in name_lower for x in [
            "shoe", "shoes", "sneaker",
            "sandals", "slipper", "boots"
        ]):
            category = "Footwear"

            if any(x in name_lower for x in [
                "sport", "running", "nike", "adidas"
            ]):
                subcategory = "Sports Shoes"

            elif any(x in name_lower for x in [
                "sandal", "slipper"
            ]):
                subcategory = "Sandals"

            else:
                subcategory = "Men"

        # =====================================================
        # BEAUTY
        # =====================================================

        elif any(x in name_lower for x in [
            "cream", "face", "makeup", "lipstick",
            "shampoo", "perfume", "beauty"
        ]):
            category = "Beauty"
            subcategory = "Beauty"

        # =====================================================
        # BAGS
        # =====================================================

        elif any(x in name_lower for x in [
            "bag", "backpack", "luggage"
        ]):
            category = "Bags"
            subcategory = "Bags"

        # =====================================================
        # FURNITURE
        # =====================================================

        elif any(x in name_lower for x in [
            "chair", "table", "sofa", "bed",
            "furniture", "wardrobe"
        ]):
            category = "Furniture"

            if any(x in name_lower for x in [
                "chair", "office chair"
            ]):
                subcategory = "Chairs"

            elif any(x in name_lower for x in [
                "sofa", "couch"
            ]):
                subcategory = "Living Room"

            elif any(x in name_lower for x in [
                "bed", "wardrobe"
            ]):
                subcategory = "Bedroom"

            else:
                subcategory = "Furniture"

        # =====================================================
        # GAMING
        # =====================================================

        elif any(x in name_lower for x in [
            "game", "gaming", "playstation",
            "xbox", "controller"
        ]):
            category = "Gaming"
            subcategory = "Gaming"

        # =====================================================
        # BOOKS
        # =====================================================

        elif any(x in name_lower for x in [
            "book", "novel", "textbook"
        ]):
            category = "Books"
            subcategory = "Books"

        # =====================================================
        # DEFAULT
        # =====================================================

        else:
            category = "General"
            subcategory = "General"

        db.execute(
            """
            UPDATE products
            SET category = ?,
                subcategory = ?
            WHERE id = ?
            """,
            (
                category,
                subcategory,
                product_id
            )
        )

    db.commit()
    db.close()


def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS business (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price TEXT,
            description TEXT
        )
    """)

    # Add category column to old databases
    try:
        cur.execute(
            "ALTER TABLE products ADD COLUMN category TEXT DEFAULT 'General'"
        )
    except sqlite3.OperationalError:
        # Column already exists
        pass

    # Add subcategory column
    try:
        cur.execute(
            "ALTER TABLE products ADD COLUMN subcategory TEXT DEFAULT ''"
        )
    except sqlite3.OperationalError:
        pass

    # Add image_url column
    try:
        cur.execute(
            "ALTER TABLE products ADD COLUMN image_url TEXT DEFAULT ''"
        )
    except sqlite3.OperationalError:
        pass

    # Add stock column
    try:
        cur.execute(
            "ALTER TABLE products ADD COLUMN stock INTEGER DEFAULT 0"
        )
    except sqlite3.OperationalError:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS faqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_number TEXT UNIQUE NOT NULL,
            customer_name TEXT NOT NULL,
            product_name TEXT NOT NULL,
            price TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            expected_delivery TEXT
        )
    """)

    # =========================================================
    # ORDER EXTRA FIELDS
    # =========================================================

    order_columns = [
        ("phone", "TEXT DEFAULT ''"),
        ("address", "TEXT DEFAULT ''"),
        ("city", "TEXT DEFAULT ''"),
        ("pincode", "TEXT DEFAULT ''"),
        ("payment_method", "TEXT DEFAULT 'UPI'"),
        ("payment_status", "TEXT DEFAULT 'Pending'"),
        ("upi_id", "TEXT DEFAULT ''"),
        ("utr", "TEXT DEFAULT ''"),
        ("card_holder_name", "TEXT DEFAULT ''"),
        ("card_last4", "TEXT DEFAULT ''"),
        ("emi_provider", "TEXT DEFAULT ''"),
        ("emi_tenure", "TEXT DEFAULT ''"),
        ("emi_reference", "TEXT DEFAULT ''"),
        ("created_at", "TEXT DEFAULT ''")
    ]

    for column_name, column_type in order_columns:

        try:

            cur.execute(
                f"""
                ALTER TABLE orders
                ADD COLUMN {column_name}
                {column_type}
                """
            )

        except sqlite3.OperationalError:
            # Column already exists
            pass

    # Categories table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    default_categories = [
        "Electronics",
        "Mobiles",
        "Laptops",
        "Audio",
        "Fashion",
        "Clothing",
        "Footwear",
        "Accessories",
        "Home & Kitchen",
        "Beauty",
        "Sports",
        "Gaming",
        "Books",
        "Toys",
        "Grocery",
        "Automotive",
        "Furniture",
        "Personal Care",
        "Stationery",
        "Other"
    ]

    for category in default_categories:
        cur.execute(
            "INSERT OR IGNORE INTO categories (name) VALUES (?)",
            (category,)
        )

    cur.execute("""
        INSERT OR IGNORE INTO business
        (id, name, description)
        VALUES
        (1, 'My Business', 'Welcome to our business.')
    """)

    db.commit()
    db.close()

    # Run migration once to clean existing prices
    clean_existing_prices()

    # Assign categories to existing products
    assign_product_categories()


init_db()


# =========================================================
# MODELS
# =========================================================

class ChatRequest(BaseModel):
    message: str


class CheckoutOrder(BaseModel):
    order_number: str
    customer_name: str
    product_name: str
    price: str

    phone: str = ""
    address: str = ""
    city: str = ""
    pincode: str = ""

    payment: str = "UPI"
    upi_id: str = ""
    utr: str = ""

    # IMPORTANT:
    # Cart is sent using product IDs, so checkout
    # never depends on product-name matching.
    cart: dict[str, int] = {}


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_business():
    db = get_db()
    result = db.execute(
        "SELECT name, description FROM business WHERE id = 1"
    ).fetchone()
    db.close()

    return result or (
        "My Business",
        "Welcome to our business."
    )


def get_products():
    db = get_db()
    result = db.execute("""
        SELECT
            id,
            name,
            price,
            description,
            category,
            subcategory,
            image_url,
            stock
        FROM products
        ORDER BY id DESC
    """).fetchall()
    db.close()
    return result


def get_categories():
    db = get_db()
    result = db.execute("""
        SELECT id, name
        FROM categories
        ORDER BY name ASC
    """).fetchall()
    db.close()
    return result


def get_faqs():
    db = get_db()
    result = db.execute("""
        SELECT id, question, answer
        FROM faqs
        ORDER BY id DESC
    """).fetchall()
    db.close()

    return result


def get_orders():

    db = get_db()

    result = db.execute(
        """
        SELECT

            o.id,

            o.order_number,

            o.customer_name,

            o.product_name,

            CASE
                WHEN o.price IS NOT NULL
                AND TRIM(o.price) != ''
                THEN o.price
                ELSE p.price
            END AS price,

            o.status,

            o.expected_delivery,

            o.phone,

            o.address,

            o.city,

            o.pincode,

            o.payment_method,

            o.payment_status,

            o.upi_id,

            o.utr,

            o.card_holder_name,

            o.card_last4,

            o.emi_provider,

            o.emi_tenure,

            o.emi_reference,

            o.created_at

        FROM orders o

        LEFT JOIN products p

            ON LOWER(TRIM(o.product_name))
             = LOWER(TRIM(p.name))

        ORDER BY o.id DESC
        """
    ).fetchall()

    db.close()

    return result


def get_order(order_number):

    db = get_db()

    order = db.execute("""
        SELECT
            order_number,
            customer_name,
            product_name,
            price,
            status,
            expected_delivery,
            phone,
            address,
            city,
            pincode,
            payment_method,
            payment_status,
            upi_id,
            utr,
            card_holder_name,
            card_last4,
            emi_provider,
            emi_tenure,
            emi_reference,
            created_at

        FROM orders

        WHERE LOWER(TRIM(order_number))
            = LOWER(TRIM(?))

        LIMIT 1
    """, (order_number,)).fetchone()

    db.close()

    return order


def get_category_icon(name):

    value = (
        str(name or "")
        .strip()
        .lower()
    )

    icons = {

        "smartphones": "📱",
        "smartphone": "📱",
        "phones": "📱",
        "mobile": "📱",

        "laptops": "💻",
        "laptop": "💻",

        "tablets": "📲",
        "tablet": "📲",

        "televisions": "📺",
        "television": "📺",
        "tv": "📺",

        "audio": "🎧",
        "headphones": "🎧",
        "earbuds": "🎧",

        "smart watches": "⌚",
        "smartwatch": "⌚",
        "smart watch": "⌚",
        "watches": "⌚",

        "cameras": "📷",
        "camera": "📷",

        "gaming": "🎮",
        "gaming accessories": "🎮",

        "accessories": "🔌",

        "stationery": "✏️",
        "books": "📚",

        "fashion": "👕",
        "shoes": "👟",

        "beauty": "💄",

        "home": "🏠",
        "furniture": "🛋️",

        "sports": "⚽",

        "groceries": "🛒"
    }

    return icons.get(
        value,
        "🛍️"
    )


# =========================================================
# PRODUCT HELPER FUNCTIONS
# =========================================================

def get_product_subcategory(name, category=""):
    name = (name or "").lower().strip()
    category = (category or "").lower().strip()

    # =====================================================
    # ELECTRONICS
    # =====================================================

    if category == "electronics":

        if any(x in name for x in [
            "iphone", "ipad", "samsung galaxy",
            "oneplus", "pixel", "redmi",
            "realme", "vivo", "oppo",
            "phone", "mobile", "smartphone"
        ]):
            return "Smartphones"

        if any(x in name for x in [
            "laptop", "macbook", "notebook pc",
            "chromebook", "thinkpad", "ideapad"
        ]):
            return "Laptops"

        if any(x in name for x in [
            "tablet", "ipad"
        ]):
            return "Tablets"

        if any(x in name for x in [
            "tv", "television", "smart tv",
            "led tv", "oled", "qled"
        ]):
            return "Televisions"

        if any(x in name for x in [
            "airpods", "earbuds", "headphone",
            "headphones", "speaker", "soundbar",
            "earphone"
        ]):
            return "Audio"

        if any(x in name for x in [
            "watch", "smartwatch", "galaxy watch",
            "apple watch"
        ]):
            return "Smart Watches"

        if any(x in name for x in [
            "camera", "dslr", "mirrorless",
            "gopro"
        ]):
            return "Cameras"

        if any(x in name for x in [
            "playstation", "ps5", "ps4",
            "xbox", "nintendo", "gaming console"
        ]):
            return "Gaming"

        return "Accessories"

    # =====================================================
    # CLOTHING
    # =====================================================

    if category == "clothing":

        if any(x in name for x in [
            "men", "mens", "man", "shirt", "kurta"
        ]):
            return "Men"

        if any(x in name for x in [
            "women", "womens", "woman", "saree"
        ]):
            return "Women"

        if any(x in name for x in [
            "kid", "kids", "children", "child"
        ]):
            return "Kids"

        if any(x in name for x in [
            "ethnic", "kurta", "saree"
        ]):
            return "Ethnic Wear"

        return "Western Wear"

    # =====================================================
    # KIDS
    # =====================================================

    if category == "kids":

        if any(x in name for x in [
            "toy", "teddy", "lego"
        ]):
            return "Toys"

        if any(x in name for x in [
            "baby", "diaper", "feeding"
        ]):
            return "Baby Products"

        if any(x in name for x in [
            "school", "bag", "pencil"
        ]):
            return "Kids School"

        return "Kids Games"

    # =====================================================
    # STATIONERY
    # =====================================================

    if category == "stationery":

        if "pen" in name:
            return "Pens"

        if "pencil" in name:
            return "Pencils"

        if any(x in name for x in [
            "notebook", "notepad", "diary"
        ]):
            return "Notebooks"

        if any(x in name for x in [
            "paint", "colour", "color", "brush"
        ]):
            return "Art Supplies"

        return "School Supplies"

    # =====================================================
    # FOOTWEAR
    # =====================================================

    if category == "footwear":

        if any(x in name for x in [
            "sport", "running", "nike", "adidas"
        ]):
            return "Sports Shoes"

        if any(x in name for x in [
            "sandal", "slipper"
        ]):
            return "Sandals"

        if any(x in name for x in [
            "kid", "kids", "children"
        ]):
            return "Kids"

        if any(x in name for x in [
            "women", "womens"
        ]):
            return "Women"

        return "Men"

    # =====================================================
    # BEAUTY
    # =====================================================

    if category == "beauty":

        if any(x in name for x in [
            "cream", "face", "serum", "moisturizer"
        ]):
            return "Skin Care"

        if any(x in name for x in [
            "shampoo", "conditioner", "hair"
        ]):
            return "Hair Care"

        if any(x in name for x in [
            "lipstick", "foundation", "makeup"
        ]):
            return "Makeup"

        return "Fragrances"

    # =====================================================
    # GAMING
    # =====================================================

    if category == "gaming":

        if any(x in name for x in [
            "ps5", "ps4", "xbox", "console"
        ]):
            return "Consoles"

        if any(x in name for x in [
            "game", "gta", "fifa"
        ]):
            return "Games"

        if any(x in name for x in [
            "controller", "gamepad"
        ]):
            return "Controllers"

        return "PC Gaming"

    # =====================================================
    # BAGS
    # =====================================================

    if category == "bags":

        if any(x in name for x in [
            "backpack", "school bag"
        ]):
            return "Backpacks"

        if "luggage" in name:
            return "Luggage"

        if any(x in name for x in [
            "handbag", "hand bag"
        ]):
            return "Hand Bags"

        return "Bags"

    # =====================================================
    # FURNITURE
    # =====================================================

    if category == "furniture":

        if any(x in name for x in [
            "chair", "office chair"
        ]):
            return "Chairs"

        if any(x in name for x in [
            "sofa", "couch"
        ]):
            return "Living Room"

        if any(x in name for x in [
            "bed", "wardrobe"
        ]):
            return "Bedroom"

        return "Furniture"

    return ""


def get_product_icon(name, category="", subcategory=""):

    text = (
        (name or "") + " " +
        (category or "") + " " +
        (subcategory or "")
    ).lower()

    # =====================================================
    # PHONES
    # =====================================================

    if any(x in text for x in [
        "iphone", "phone", "mobile",
        "smartphone", "galaxy", "pixel",
        "oneplus", "redmi", "realme"
    ]):
        return "📱"

    # =====================================================
    # LAPTOPS
    # =====================================================

    if any(x in text for x in [
        "laptop", "macbook", "notebook"
    ]):
        return "💻"

    # =====================================================
    # TABLETS
    # =====================================================

    if any(x in text for x in [
        "tablet", "ipad"
    ]):
        return "📲"

    # =====================================================
    # TV
    # =====================================================

    if any(x in text for x in [
        "tv", "television", "oled", "qled"
    ]):
        return "📺"

    # =====================================================
    # AUDIO
    # =====================================================

    if any(x in text for x in [
        "airpods", "earbuds",
        "headphone", "earphone"
    ]):
        return "🎧"

    # =====================================================
    # SPEAKER
    # =====================================================

    if any(x in text for x in [
        "speaker", "soundbar"
    ]):
        return "🔊"

    # =====================================================
    # SMART WATCH
    # =====================================================

    if any(x in text for x in [
        "watch", "smartwatch"
    ]):
        return "⌚"

    # =====================================================
    # CAMERA
    # =====================================================

    if any(x in text for x in [
        "camera", "dslr", "gopro"
    ]):
        return "📷"

    # =====================================================
    # CLOTHING
    # =====================================================

    if any(x in text for x in [
        "shirt", "t-shirt", "jeans", "dress",
        "hoodie", "jacket", "clothing",
        "kurta", "saree"
    ]):
        return "👕"

    # =====================================================
    # FOOTWEAR
    # =====================================================

    if any(x in text for x in [
        "shoe", "shoes", "sneaker",
        "sandals", "slipper", "boots",
        "footwear"
    ]):
        return "👟"

    # =====================================================
    # BOOKS
    # =====================================================

    if any(x in text for x in [
        "book", "novel"
    ]):
        return "📚"

    # =====================================================
    # STATIONERY
    # =====================================================

    if any(x in text for x in [
        "pen", "pencil", "stationery",
        "marker", "eraser"
    ]):
        return "✏️"

    # =====================================================
    # TOYS / KIDS
    # =====================================================

    if any(x in text for x in [
        "toy", "teddy", "lego", "kids",
        "kid", "baby"
    ]):
        return "🧸"

    # =====================================================
    # HOME / FURNITURE
    # =====================================================

    if any(x in text for x in [
        "chair", "table", "sofa", "furniture",
        "home", "kitchen"
    ]):
        return "🏠"

    # =====================================================
    # BAGS
    # =====================================================

    if any(x in text for x in [
        "bag", "backpack", "luggage"
    ]):
        return "🎒"

    # =====================================================
    # BEAUTY
    # =====================================================

    if any(x in text for x in [
        "cream", "makeup", "lipstick",
        "shampoo", "perfume", "beauty"
    ]):
        return "💄"

    # =====================================================
    # GAMING
    # =====================================================

    if any(x in text for x in [
        "gaming", "game", "playstation",
        "xbox", "controller", "gamepad"
    ]):
        return "🎮"

    # =====================================================
    # GROCERY
    # =====================================================

    if any(x in text for x in [
        "grocery", "food", "rice", "flour",
        "snack", "drink"
    ]):
        return "🛒"

    return "📦"


# =========================================================
# CUSTOMER CHAT PAGE
# =========================================================

CHAT_PAGE = """
<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>AI Business Assistant</title>

<style>

* {
    box-sizing: border-box;
}

:root {
    --glass: rgba(255,255,255,.07);
    --glass-strong: rgba(255,255,255,.11);
    --border: rgba(255,255,255,.12);
    --text: #f8fafc;
    --muted: #94a3b8;
    --blue: #4f7cff;
}

body {
    margin: 0;
    min-height: 100vh;
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    color: var(--text);

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(80,110,255,.25),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(120,70,255,.22),
            transparent 30%
        ),
        #070b16;

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 24px;
}

body::before {
    content: "";
    position: fixed;
    inset: 0;

    pointer-events: none;

    background:
        linear-gradient(
            120deg,
            rgba(255,255,255,.035),
            transparent 40%
        );
}

.app {
    width: 100%;
    max-width: 1250px;
    height: 88vh;

    display: flex;

    overflow: hidden;

    border-radius: 30px;

    background:
        rgba(15,23,42,.58);

    border:
        1px solid var(--border);

    backdrop-filter:
        blur(35px)
        saturate(160%);

    -webkit-backdrop-filter:
        blur(35px)
        saturate(160%);

    box-shadow:
        0 30px 100px rgba(0,0,0,.5),
        inset 0 1px rgba(255,255,255,.08);
}


/* SIDEBAR */

.sidebar {
    width: 280px;

    padding: 25px;

    display: flex;
    flex-direction: column;

    background:
        rgba(255,255,255,.025);

    border-right:
        1px solid rgba(255,255,255,.08);
}

.logo {
    display: flex;
    align-items: center;
    gap: 12px;

    margin-bottom: 35px;
}

.logo-icon {
    width: 46px;
    height: 46px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 15px;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #764cff
        );

    box-shadow:
        0 10px 35px rgba(79,124,255,.35);
}

.logo h2 {
    margin: 0;
    font-size: 17px;
}

.logo span {
    color: #64748b;
    font-size: 11px;
}


/* NAV */

.nav-title {
    color: #64748b;
    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: 1.5px;

    margin-bottom: 10px;
}

.nav {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.nav a {
    text-decoration: none;

    color: #aab5c8;

    padding: 12px;

    border-radius: 13px;

    transition: .2s;
}

.nav a:hover {
    color: white;

    background:
        rgba(255,255,255,.07);

    transform:
        translateX(2px);
}


/* BOTTOM */

.sidebar-bottom {
    margin-top: auto;
}

.online {
    display: flex;
    align-items: center;
    gap: 8px;

    padding: 12px;

    border-radius: 13px;

    background:
        rgba(34,197,94,.07);

    border:
        1px solid rgba(34,197,94,.12);

    color: #94a3b8;

    font-size: 12px;
}

.dot {
    width: 7px;
    height: 7px;

    border-radius: 50%;

    background: #22c55e;

    box-shadow:
        0 0 12px #22c55e;
}


/* MAIN */

.main {
    flex: 1;

    min-width: 0;

    display: flex;
    flex-direction: column;
}


/* HEADER */

.header {
    height: 75px;

    padding: 0 25px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    border-bottom:
        1px solid rgba(255,255,255,.07);
}

.header h1 {
    margin: 0;

    font-size: 18px;
}

.header p {
    margin: 4px 0 0;

    color: #64748b;

    font-size: 11px;
}

.badge {
    padding: 8px 13px;

    border-radius: 20px;

    color: #9bb8ff;

    background:
        rgba(79,124,255,.1);

    border:
        1px solid rgba(79,124,255,.18);

    font-size: 11px;
}


/* CHAT */

#chat {
    flex: 1;

    padding: 30px;

    overflow-y: auto;
}

.message {
    display: flex;

    gap: 10px;

    margin-bottom: 22px;
}

.avatar {
    width: 35px;
    height: 35px;

    flex-shrink: 0;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #764cff
        );
}

.bubble {
    max-width: 720px;

    padding: 15px 18px;

    border-radius: 18px;

    background:
        rgba(255,255,255,.065);

    border:
        1px solid rgba(255,255,255,.08);

    backdrop-filter:
        blur(20px);

    line-height: 1.6;

    color: #dbe4f5;

    font-size: 14px;
}

.user {
    justify-content: flex-end;
}

.user .avatar {
    order: 2;

    background:
        rgba(255,255,255,.08);
}

.user .bubble {
    background:
        linear-gradient(
            135deg,
            #416cff,
            #6248e8
        );

    color: white;
}


/* QUICK CARDS */

#quickOptions {
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    padding: 0 30px 20px;
}

#quickOptions a {
    text-decoration: none;

    padding: 17px;

    border-radius: 18px;

    color: white;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid rgba(255,255,255,.08);

    backdrop-filter:
        blur(18px);

    transition: .25s;
}

#quickOptions a:hover {
    background:
        rgba(255,255,255,.09);

    border-color:
        rgba(255,255,255,.17);

    transform:
        translateY(-3px);
}

.quick-icon {
    font-size: 20px;

    margin-bottom: 8px;
}

.quick-title {
    font-size: 13px;

    font-weight: 600;
}

.quick-text {
    margin-top: 4px;

    color: #64748b;

    font-size: 10px;
}


/* INPUT */

.input-area {
    padding:
        15px 25px 20px;
}

.input-box {
    display: flex;

    gap: 10px;

    padding: 7px;

    border-radius: 17px;

    background:
        rgba(255,255,255,.055);

    border:
        1px solid rgba(255,255,255,.12);

    backdrop-filter:
        blur(25px);
}

#message {
    flex: 1;

    min-width: 0;

    border: 0;
    outline: 0;

    background: transparent;

    color: white;

    padding: 11px;

    font-size: 14px;
}

#message::placeholder {
    color: #475569;
}

.send {
    width: 43px;
    height: 43px;

    border: 0;

    border-radius: 13px;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #6748ec
        );

    color: white;

    cursor: pointer;

    font-size: 17px;
}


/* MOBILE */

@media(max-width: 750px) {

    body {
        padding: 0;
    }

    .app {
        height: 100vh;
        border-radius: 0;
    }

    .sidebar {
        display: none;
    }

    #quickOptions {
        grid-template-columns:
            repeat(1,1fr);

        padding:
            0 18px 15px;
    }

    #chat {
        padding: 20px 18px;
    }

    .bubble {
        max-width: 85%;
    }

}

</style>
</head>


<body>

<div class="app">


    <aside class="sidebar">

        <div class="logo">

            <div class="logo-icon">
                ✦
            </div>

            <div>
                <h2>AI Assistant</h2>
                <span>Business Intelligence</span>
            </div>

        </div>


        <div class="nav-title">
            Workspace
        </div>


        <nav class="nav">

            <a href="/">
                ✦ AI Assistant
            </a>

            <a href="/products">
                🛍️ Products
            </a>

            <a href="/orders">
                📦 Orders
            </a>

            <a href="/support">
                💬 Customer Support
            </a>

            <a href="/faq">
                ❓ FAQ
            </a>

            <a href="/about">
                🏪 About Business
            </a>

        </nav>


        <div class="sidebar-bottom">

            <div class="online">
                <span class="dot"></span>
                AI Assistant Online
            </div>

            <div style="height:10px"></div>

            <button
                onclick="restartChat()"
                style="
                    width:100%;
                    padding:12px;
                    border-radius:13px;
                    border:1px solid rgba(255,255,255,.08);
                    background:rgba(255,255,255,.05);
                    color:#aab5c8;
                    cursor:pointer;
                    font-size:12px;
                    transition:.2s;
                "
                onmouseover="this.style.background='rgba(255,255,255,.09)'"
                onmouseout="this.style.background='rgba(255,255,255,.05)'"
            >
                ↻ New Chat
            </button>

            <div style="height:8px"></div>

            <a
                href="/admin"
                style="
                    color:#64748b;
                    text-decoration:none;
                    font-size:12px;
                    display:block;
                    text-align:center;
                "
            >
                ⚙️ Business Admin
            </a>

        </div>

    </aside>


    <main class="main">


        
            <div>
                <h1>AI Business Assistant</h1>

                <p>
                    Your intelligent customer support
                </p>
            </div>

            <div class="badge">
                ● AI Online
            </div><header class="header">


        </header>


        <div id="chat">

            <div class="message assistant">

                <div class="avatar">
                    ✦
                </div>

                <div class="bubble">

                    👋 Hello! Welcome to our business.

                    <br><br>

                    I can help you with products,
                    orders, support and general enquiries.

                </div>

            </div>

        </div>


        <div id="quickOptions" class="quick">

            <a href="/products">

                <div class="quick-icon">
                    🛍️
                </div>

                <div class="quick-title">
                    View Products
                </div>

                <div class="quick-text">
                    Browse our complete catalog
                </div>

            </a>


            <a href="/orders">

                <div class="quick-icon">
                    📦
                </div>

                <div class="quick-title">
                    Track Order
                </div>

                <div class="quick-text">
                    Check your order status
                </div>

            </a>


            <a href="/support">

                <div class="quick-icon">
                    💬
                </div>

                <div class="quick-title">
                    Customer Support
                </div>

                <div class="quick-text">
                    Get help from our assistant
                </div>

            </a>

        </div>


        <div class="input-area">

            <div class="input-box">

                <input
                    id="message"
                    placeholder="Ask anything about our business..."
                    autocomplete="off"
                >

                <button
                    class="send"
                    onclick="sendMessage()"
                >
                    ➤
                </button>

            </div>

        </div>


    </main>

</div>


<script>

const input =
    document.getElementById("message");

const chat =
    document.getElementById("chat");


input.addEventListener(
    "keydown",
    function(event) {

        if (event.key === "Enter") {
            sendMessage();
        }

    }
);


function addMessage(text, type) {

    const message =
        document.createElement("div");

    message.className =
        "message " + type;


    const avatar =
        document.createElement("div");

    avatar.className =
        "avatar";

    avatar.textContent =
        type === "assistant"
        ? "✦"
        : "●";


    const bubble =
        document.createElement("div");

    bubble.className =
        "bubble";

    bubble.textContent =
        text;


    if (type === "user") {

        message.appendChild(bubble);
        message.appendChild(avatar);

    } else {

        message.appendChild(avatar);
        message.appendChild(bubble);

    }


    chat.appendChild(message);

    chat.scrollTop =
        chat.scrollHeight;

    localStorage.setItem(
        "ai_business_chat",
        chat.innerHTML
    );
}


window.addEventListener("load", function() {

    const savedChat =
        localStorage.getItem("ai_business_chat");

    if (savedChat) {
        chat.innerHTML = savedChat;

        chat.scrollTop =
            chat.scrollHeight;

        const quickOptions =
            document.getElementById("quickOptions");

        if (quickOptions) {
            quickOptions.remove();
        }
    }
});

function exitChat() {
    const confirmExit = confirm(
        "Exit chat? Your current chat history will be cleared."
    );

    if (!confirmExit) {
        return;
    }

    localStorage.removeItem("ai_business_chat");
    window.location.href = "/support";
}

function restartChat() {

    localStorage.removeItem(
        "ai_business_chat"
    );

    location.reload();
}

async function sendMessage() {

    const text =
        input.value.trim();

    if (!text) return;

    const quickOptions =
        document.getElementById("quickOptions");

    if (quickOptions) {
        quickOptions.remove();
    }

    addMessage(text, "user");

    input.value = "";


    try {

        const response =
            await fetch("/chat", {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    message: text
                })

            });


        const data =
            await response.json();


        addMessage(
            data.reply ||
            "Sorry, something went wrong.",
            "assistant"
        );


    } catch(error) {

        addMessage(
            "Sorry! Please try again.",
            "assistant"
        );

    }

}

</script>

</body>
</html>
"""

# Customer Support = same chat, but without quick cards
SUPPORT_CHAT_PAGE = CHAT_PAGE.replace(
    '<div id="quickOptions" class="quick">',
    '<div id="quickOptions" class="quick" style="display:none;">',
    1
)


# =========================================================
# SKYE MART HOME + CATEGORY SYSTEM
# =========================================================

CATEGORY_MAP = {
    "electronics": {
        "name": "Electronics",
        "icon": "📱",
        "subcategories": {
            "smartphones": {
                "name": "Smartphones",
                "icon": "📱"
            },
            "laptops": {
                "name": "Laptops",
                "icon": "💻"
            },
            "tablets": {
                "name": "Tablets",
                "icon": "📲"
            },
            "televisions": {
                "name": "Televisions",
                "icon": "📺"
            },
            "audio": {
                "name": "Audio",
                "icon": "🎧"
            },
            "smartwatches": {
                "name": "Smart Watches",
                "icon": "⌚"
            },
            "cameras": {
                "name": "Cameras",
                "icon": "📷"
            },
            "gaming": {
                "name": "Gaming",
                "icon": "🎮"
            },
            "accessories": {
                "name": "Accessories",
                "icon": "🔌"
            }
        }
    },

    "clothing": {
        "name": "Clothing",
        "icon": "👕",
        "subcategories": {
            "men": {
                "name": "Men",
                "icon": "👔"
            },
            "women": {
                "name": "Women",
                "icon": "👗"
            },
            "kids": {
                "name": "Kids",
                "icon": "🧒"
            },
            "ethnic": {
                "name": "Ethnic Wear",
                "icon": "🥻"
            },
            "western": {
                "name": "Western Wear",
                "icon": "👚"
            }
        }
    },

    "kids": {
        "name": "Kids",
        "icon": "🧸",
        "subcategories": {
            "toys": {
                "name": "Toys",
                "icon": "🧸"
            },
            "baby": {
                "name": "Baby Products",
                "icon": "🍼"
            },
            "school": {
                "name": "Kids School",
                "icon": "🎒"
            },
            "games": {
                "name": "Kids Games",
                "icon": "🎮"
            }
        }
    },

    "stationery": {
        "name": "Stationery",
        "icon": "✏️",
        "subcategories": {
            "pens": {
                "name": "Pens",
                "icon": "🖊️"
            },
            "pencils": {
                "name": "Pencils",
                "icon": "✏️"
            },
            "notebooks": {
                "name": "Notebooks",
                "icon": "📓"
            },
            "school": {
                "name": "School Supplies",
                "icon": "📚"
            },
            "art": {
                "name": "Art Supplies",
                "icon": "🎨"
            }
        }
    },

    "beauty": {
        "name": "Beauty",
        "icon": "💄",
        "subcategories": {
            "skincare": {
                "name": "Skin Care",
                "icon": "🧴"
            },
            "haircare": {
                "name": "Hair Care",
                "icon": "💇"
            },
            "makeup": {
                "name": "Makeup",
                "icon": "💄"
            },
            "fragrance": {
                "name": "Fragrances",
                "icon": "🌸"
            }
        }
    },

    "home-kitchen": {
        "name": "Home & Kitchen",
        "icon": "🏠",
        "subcategories": {
            "kitchen": {
                "name": "Kitchen",
                "icon": "🍳"
            },
            "appliances": {
                "name": "Appliances",
                "icon": "🔌"
            },
            "furniture": {
                "name": "Home Furniture",
                "icon": "🛋️"
            },
            "decor": {
                "name": "Home Decor",
                "icon": "🖼️"
            },
            "cleaning": {
                "name": "Cleaning",
                "icon": "🧹"
            }
        }
    },

    "footwear": {
        "name": "Footwear",
        "icon": "👟",
        "subcategories": {
            "men": {
                "name": "Men",
                "icon": "👞"
            },
            "women": {
                "name": "Women",
                "icon": "👠"
            },
            "kids": {
                "name": "Kids",
                "icon": "👟"
            },
            "sports": {
                "name": "Sports Shoes",
                "icon": "🏃"
            },
            "sandals": {
                "name": "Sandals",
                "icon": "🩴"
            }
        }
    },

    "gaming": {
        "name": "Gaming",
        "icon": "🎮",
        "subcategories": {
            "consoles": {
                "name": "Consoles",
                "icon": "🎮"
            },
            "games": {
                "name": "Games",
                "icon": "🎯"
            },
            "controllers": {
                "name": "Controllers",
                "icon": "🕹️"
            },
            "pc": {
                "name": "PC Gaming",
                "icon": "💻"
            },
            "accessories": {
                "name": "Accessories",
                "icon": "🔌"
            }
        }
    },

    "grocery": {
        "name": "Grocery",
        "icon": "🛒",
        "subcategories": {
            "food": {
                "name": "Food",
                "icon": "🍞"
            },
            "snacks": {
                "name": "Snacks",
                "icon": "🍿"
            },
            "beverages": {
                "name": "Beverages",
                "icon": "🥤"
            },
            "household": {
                "name": "Household",
                "icon": "🧻"
            }
        }
    },

    "bags": {
        "name": "Bags",
        "icon": "🎒",
        "subcategories": {
            "backpacks": {
                "name": "Backpacks",
                "icon": "🎒"
            },
            "school": {
                "name": "School Bags",
                "icon": "🎒"
            },
            "luggage": {
                "name": "Luggage",
                "icon": "🧳"
            },
            "handbags": {
                "name": "Hand Bags",
                "icon": "👜"
            }
        }
    },

    "automotive": {
        "name": "Automotive",
        "icon": "🚗",
        "subcategories": {
            "car": {
                "name": "Car Accessories",
                "icon": "🚗"
            },
            "bike": {
                "name": "Bike Accessories",
                "icon": "🏍️"
            },
            "tools": {
                "name": "Tools",
                "icon": "🔧"
            }
        }
    },

    "sports": {
        "name": "Sports",
        "icon": "⚽",
        "subcategories": {
            "cricket": {
                "name": "Cricket",
                "icon": "🏏"
            },
            "football": {
                "name": "Football",
                "icon": "⚽"
            },
            "fitness": {
                "name": "Fitness",
                "icon": "💪"
            },
            "badminton": {
                "name": "Badminton",
                "icon": "🏸"
            }
        }
    },

    "books": {
        "name": "Books",
        "icon": "📖",
        "subcategories": {
            "school": {
                "name": "School Books",
                "icon": "📚"
            },
            "college": {
                "name": "College Books",
                "icon": "📖"
            },
            "fiction": {
                "name": "Fiction",
                "icon": "📕"
            },
            "nonfiction": {
                "name": "Non Fiction",
                "icon": "📘"
            }
        }
    },

    "furniture": {
        "name": "Furniture",
        "icon": "🛋️",
        "subcategories": {
            "bedroom": {
                "name": "Bedroom",
                "icon": "🛏️"
            },
            "living": {
                "name": "Living Room",
                "icon": "🛋️"
            },
            "office": {
                "name": "Office",
                "icon": "💼"
            },
            "chairs": {
                "name": "Chairs",
                "icon": "🪑"
            }
        }
    }
}


@app.get("/", response_class=HTMLResponse)
def home():

    db = get_db()

    products = db.execute("""
        SELECT
            id,
            name,
            price,
            description,
            category,
            subcategory,
            image_url,
            stock
        FROM products
        ORDER BY id DESC
    """).fetchall()

    db.close()

    # =========================================================
    # CATEGORY HTML
    # =========================================================

    category_html = ""

    for slug, data in CATEGORY_MAP.items():

        category_html += f"""
        <a
            href="/category/{slug}"
            class="shop-category"
        >

            <span class="category-icon">
                {data["icon"]}
            </span>

            <span class="category-name">
                {html.escape(data["name"])}
            </span>

            <span class="category-shine"></span>

        </a>
        """

    # =========================================================
    # PRODUCTS
    # =========================================================

    products_html = ""

    for product in products:

        product_id = product[0]

        name = html.escape(product[1] or "")
        price = html.escape(str(product[2] or ""))
        description = html.escape(product[3] or "")
        image_url = html.escape(product[6] or "")

        try:
            stock = int(product[7] or 0)
        except (ValueError, TypeError):
            stock = 0

        product_icon = get_product_icon(
            product[1],
            product[4],
            product[5]
        )

        # Product image display
        if image_url:
            image_display = f"""
            <img
                src="{image_url}"
                alt="{name}"
                class="product-real-image"
                onerror="this.style.display='none';"
            >
            """
        else:
            image_display = f"""
            <div class="product-fallback-icon">
                {product_icon}
            </div>
            """

        stock_warning = ""

        if stock <= 0:
            stock_warning = """
            <div style="
                margin-top:8px;
                color:#f87171;
                font-size:11px;
                font-weight:700;
            ">
                Out of stock
            </div>
            """
        elif stock < 10:
            stock_warning = f"""
            <div style="
                margin-top:8px;
                color:#fbbf24;
                font-size:11px;
                font-weight:700;
            ">
                Only {stock} left
            </div>
            """

        products_html += f"""
        <a
            href="/products/{product_id}"
            class="shop-product"
        >

            <div class="shop-product-image">
                {image_display}
            </div>

            <div class="shop-product-info">

                <h3>
                    {name}
                </h3>

                <p>
                    {description}
                </p>

                <strong>
                    ₹{price}
                </strong>

                {stock_warning}

            </div>

        </a>
        """

    if not products_html:

        products_html = """
        <div class="shop-empty">
            No products available yet.
        </div>
        """

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Skye Mart</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(79,124,255,.18),
            transparent 30%
        ),
        radial-gradient(
            circle at 90% 100%,
            rgba(118,76,255,.15),
            transparent 30%
        ),
        #070b16;

    color: #f8fafc;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}}

.shop-container {{
    width: min(
        1250px,
        calc(100% - 24px)
    );

    margin: auto;

    padding: 18px 0 50px;
}}


/* =========================
   HEADER
========================= */

.shop-header {{
    position: sticky;

    top: 12px;

    z-index: 50;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 15px 18px;

    border-radius: 20px;

    background:
        rgba(17,24,45,.82);

    border:
        1px solid rgba(255,255,255,.09);

    backdrop-filter: blur(25px);
}}

.shop-brand {{
    display: flex;

    align-items: center;

    gap: 11px;
}}

.shop-logo {{
    width: 45px;
    height: 45px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 14px;

    overflow: hidden;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #744cff
        );

    box-shadow:
        0 8px 30px rgba(79,124,255,.30);
}}

.shop-logo img {{
    width: 100%;
    height: 100%;

    object-fit: cover;

    display: block;
}}

.shop-brand h1 {{
    margin: 0;

    font-size: 19px;
}}

.shop-brand span {{
    display: block;

    margin-top: 2px;

    color: #71809a;

    font-size: 10px;
}}

.shop-actions {{
    display: flex;

    gap: 8px;
}}

.shop-action {{
    padding: 9px 13px;

    border-radius: 11px;

    color: #dbe4f5;

    text-decoration: none;

    background:
        rgba(255,255,255,.05);

    border:
        1px solid rgba(255,255,255,.08);

    font-size: 11px;
}}


/* =========================
   HERO
========================= */

.shop-hero {{
    margin-top: 18px;

    padding: 40px 25px;

    text-align: center;

    border-radius: 25px;

    background:
        linear-gradient(
            135deg,
            rgba(79,124,255,.14),
            rgba(118,76,255,.08)
        );

    border:
        1px solid rgba(255,255,255,.08);
}}

.shop-hero h2 {{
    margin: 0;

    font-size:
        clamp(28px, 5vw, 46px);

    letter-spacing: -1px;
}}

.shop-hero p {{
    margin: 10px auto 22px;

    max-width: 600px;

    color: #7f8da5;

    font-size: 13px;

    line-height: 1.6;
}}

.shop-search {{
    width: min(650px, 100%);

    padding: 14px 17px;

    border-radius: 14px;

    border:
        1px solid rgba(255,255,255,.1);

    outline: none;

    color: white;

    background:
        rgba(4,8,20,.5);

    font-size: 13px;
}}

.shop-search:focus {{
    border-color:
        rgba(79,124,255,.7);
}}


/* =========================
   CATEGORY SLIDER
========================= */

.section-heading {{
    margin: 28px 0 12px;

    font-size: 19px;
}}

.category-slider {{
    display: flex;

    gap: 12px;

    overflow-x: auto;

    overflow-y: hidden;

    padding: 6px 4px 16px;

    scroll-behavior: smooth;

    scrollbar-width: thin;

    scroll-snap-type: x mandatory;

    -webkit-overflow-scrolling: touch;
}}

.category-slider::-webkit-scrollbar {{
    height: 4px;
}}

.category-slider::-webkit-scrollbar-thumb {{
    background: rgba(255,255,255,.2);

    border-radius: 20px;
}}

.shop-category {{
    flex: 0 0 auto;

    position: relative;

    min-width: 115px;

    padding: 16px 20px;

    display: flex;

    align-items: center;

    gap: 10px;

    text-decoration: none;

    color: #cbd5e1;

    border-radius: 18px;

    background:
        rgba(255,255,255,.06);

    border:
        1px solid rgba(255,255,255,.08);

    transition: all .3s ease;

    scroll-snap-align: start;

    cursor: pointer;

    backdrop-filter: blur(12px);

    -webkit-backdrop-filter: blur(12px);

    overflow: hidden;
}}

.shop-category .category-shine {{
    position: absolute;

    top: -50%;
    left: -50%;

    width: 200%;
    height: 200%;

    background: radial-gradient(
        circle at 30% 30%,
        rgba(255,255,255,.08),
        transparent 60%
    );

    pointer-events: none;

    opacity: 0;

    transition: opacity .4s ease;
}}

.shop-category:hover .category-shine {{
    opacity: 1;
}}

.shop-category::before {{
    content: "";

    position: absolute;

    inset: -1px;

    border-radius: inherit;

    padding: 1px;

    background: linear-gradient(
        145deg,
        rgba(255,255,255,.35),
        transparent 50%,
        rgba(255,255,255,.05)
    );

    -webkit-mask:
        linear-gradient(#fff 0 0) content-box,
        linear-gradient(#fff 0 0);

    mask:
        linear-gradient(#fff 0 0) content-box,
        linear-gradient(#fff 0 0);

    -webkit-mask-composite: xor;

    mask-composite: exclude;

    pointer-events: none;
}}

.shop-category:hover::before {{
    transform:
        rotate(18deg)
        translateX(330%);
}}

.shop-category:hover {{
    transform:
        translateY(-4px)
        scale(1.035);

    border-color:
        rgba(147,197,253,.45);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.14),
            rgba(79,124,255,.08)
        );

    box-shadow:
        0 18px 45px rgba(0,0,0,.28),
        inset 0 1px rgba(255,255,255,.16);
}}

.category-icon {{
    width: 38px;
    height: 38px;

    display: flex;

    align-items: center;
    justify-content: center;

    flex-shrink: 0;

    border-radius: 12px;

    background:
        rgba(255,255,255,.07);

    border:
        1px solid rgba(255,255,255,.08);

    font-size: 22px;

    box-shadow:
        inset 0 1px rgba(255,255,255,.08);
}}

.category-name {{
    font-size: 13px;

    font-weight: 600;

    white-space: nowrap;

    letter-spacing: -.1px;
}}


/* =========================
   PRODUCTS
========================= */

.shop-products {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fill,
            minmax(210px, 1fr)
        );

    gap: 15px;
}}

.shop-product {{
    text-decoration: none;

    color: white;

    overflow: hidden;

    border-radius: 18px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid rgba(255,255,255,.08);

    transition: .25s;
}}

.shop-product:hover {{
    transform:
        translateY(-4px);

    border-color:
        rgba(79,124,255,.35);
}}

.shop-product-image {{
    height: 170px;

    display: flex;

    align-items: center;
    justify-content: center;

    background:
        rgba(255,255,255,.035);

    font-size: 50px;
}}

.product-real-image {{
    width: 100%;
    height: 100%;

    object-fit: contain;

    display: block;

    padding: 14px;

    transition:
        transform .35s ease;
}}

.shop-product:hover .product-real-image {{
    transform:
        scale(1.06);
}}

.product-fallback-icon {{
    font-size: 62px;

    display: flex;

    align-items: center;
    justify-content: center;

    width: 100%;
    height: 100%;
}}

.shop-product-info {{
    padding: 14px;
}}

.shop-product-info h3 {{
    margin: 0 0 6px;

    font-size: 14px;
}}

.shop-product-info p {{
    height: 34px;

    overflow: hidden;

    margin: 0 0 12px;

    color: #697892;

    font-size: 10px;

    line-height: 1.5;
}}

.shop-product-info strong {{
    font-size: 17px;
}}

.shop-empty {{
    grid-column: 1 / -1;

    padding: 60px;

    text-align: center;

    color: #71809a;
}}


/* =========================
   SEARCH EMPTY
========================= */

.search-empty {{
    padding: 55px 20px;
    text-align: center;
    border-radius: 20px;
    background: rgba(255,255,255,.035);
    border: 1px solid rgba(255,255,255,.07);
    color: #71809a;
    grid-column: 1 / -1;
}}

.search-empty-icon {{
    margin-bottom: 10px;
    font-size: 48px;
}}

.search-empty h3 {{
    margin: 8px 0;
    color: #f8fafc;
    font-size: 18px;
}}

.search-empty p {{
    margin: 0;
    font-size: 12px;
}}


/* =========================
   SUPPORT
========================= */

.shop-support {{
    margin-top: 30px;

    padding: 20px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 15px;

    border-radius: 20px;

    background:
        rgba(79,124,255,.08);

    border:
        1px solid rgba(79,124,255,.13);
}}

.shop-support h3 {{
    margin: 0 0 5px;
}}

.shop-support p {{
    margin: 0;

    color: #71809a;

    font-size: 11px;
}}

.support-btn {{
    flex-shrink: 0;

    padding: 11px 15px;

    border-radius: 12px;

    color: white;

    text-decoration: none;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #704cff
        );

    font-size: 11px;
}}


/* =========================
   MOBILE
========================= */

@media(max-width:600px) {{

    .shop-container {{
        width: calc(100% - 14px);
    }}

    .shop-actions {{
        display: none;
    }}

    .shop-hero {{
        padding: 35px 15px;
    }}

    .shop-products {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .shop-product-image {{
        height: 140px;
    }}

    .shop-support {{
        flex-direction: column;

        align-items: stretch;
    }}

    .support-btn {{
        text-align: center;
    }}
}}

</style>

</head>

<body>

<div class="shop-container">


<header class="shop-header">

    <a
        href="/"
        class="shop-brand"
        style="
            text-decoration:none;
            color:inherit;
            cursor:pointer;
        "
    >
        <div class="shop-logo">
            <img
                src="/static/skye-logo.png"
                alt="Skye Mart"
            >
        </div>

        <div>
            <h1>
                Skye Mart
            </h1>

            <span>
                Smart shopping experience
            </span>
        </div>
    </a>

    <div class="shop-actions">

        <a
            href="/orders"
            class="shop-action"
        >
            📦 Orders
        </a>

        <a
            href="/support"
            class="shop-action"
        >
            💬 Support
        </a>

    </div>

</header>


<section class="shop-hero">

    <h2>
        Shop everything you need.
    </h2>

    <p>
        Browse categories, discover products
        and find exactly what you're looking for.
    </p>

    <input
        id="shopSearch"
        class="shop-search"
        placeholder="🔍 Search products..."
        oninput="searchProducts()"
    >

</section>


<h2 class="section-heading">
    Categories
</h2>


<div class="category-slider" id="categorySlider">

    {category_html}

</div>


<h2 class="section-heading">
    Featured Products
</h2>


<div
    id="productGrid"
    class="shop-products"
>

    {products_html}

</div>

<div
    id="searchEmpty"
    class="search-empty"
    style="display:none;"
>
    <div class="search-empty-icon">
        🔍
    </div>

    <h3>
        Product not available
    </h3>

    <p>
        We couldn't find this product.
        Try another product name.
    </p>
</div>


<section class="shop-support">

    <div>

        <h3>
            🤖 Need help?
        </h3>

        <p>
            Ask our AI assistant about products,
            orders or anything else.
        </p>

    </div>

    <a
        href="/support"
        class="support-btn"
    >
        Customer Support →
    </a>

</section>


</div>


<script>

function searchProducts() {{

    const input =
        document.getElementById("shopSearch");

    const query =
        input.value
            .toLowerCase()
            .trim();

    const products =
        document.querySelectorAll(".shop-product");

    const empty =
        document.getElementById("searchEmpty");

    let found = 0;

    products.forEach(function(product) {{

        const text =
            product.innerText
                .toLowerCase();

        const match =
            query === "" ||
            text.includes(query);

        product.style.display =
            match ? "" : "none";

        if (match) {{
            found++;
        }}

    }});

    if (query === "") {{

        empty.style.display = "none";

        return;
    }}

    if (found === 0) {{

        empty.style.display = "block";

    }} else {{

        empty.style.display = "none";

    }}

}}

</script>


<script>
document.addEventListener("DOMContentLoaded", function () {{

    const slider =
        document.getElementById("categorySlider");

    if (!slider) return;

    /* Mouse wheel -> horizontal scroll */
    slider.addEventListener(
        "wheel",
        function (event) {{

            if (
                Math.abs(event.deltaY) >
                Math.abs(event.deltaX)
            ) {{
                event.preventDefault();

                slider.scrollBy({{
                    left: event.deltaY * 1.4,
                    behavior: "smooth"
                }});
            }}

        }},
        {{
            passive: false
        }}
    );

}});
</script>


</body>

</html>
"""


# =========================================================
# CATEGORY + SUBCATEGORY PAGES
# =========================================================

@app.get(
    "/category/{category_slug}",
    response_class=HTMLResponse
)
def category_page(category_slug: str):

    if category_slug not in CATEGORY_MAP:
        return RedirectResponse("/", status_code=303)

    data = CATEGORY_MAP[category_slug]

    category_name = data["name"]
    category_icon = data["icon"]
    subcategories = data["subcategories"]

    # Convert subcategories to items with icons
    subcategory_items = {}
    for slug, value in subcategories.items():
        if isinstance(value, dict):
            subcategory_items[slug] = {
                "name": value["name"],
                "icon": value.get("icon", category_icon)
            }
        else:
            subcategory_items[slug] = {
                "name": value,
                "icon": category_icon
            }

    db = get_db()

    products = db.execute("""
        SELECT
            id,
            name,
            price,
            description,
            category,
            subcategory
        FROM products
        WHERE LOWER(TRIM(category))
        = LOWER(TRIM(?))
        ORDER BY id DESC
    """, (category_name,)).fetchall()

    db.close()

    # -----------------------------------------------------
    # SUBCATEGORY BUTTONS
    # -----------------------------------------------------

    subcategory_html = ""

    for slug, item in subcategory_items.items():

        subcategory_html += f"""
        <a
            href="/category/{category_slug}/{slug}"
            class="subcategory-card"
        >
            <div class="subcategory-icon">
                {item["icon"]}
            </div>

            <div class="subcategory-name">
                {html.escape(item["name"])}
            </div>

            <div class="subcategory-arrow">
                →
            </div>
        </a>
        """

    # -----------------------------------------------------
    # PRODUCTS
    # -----------------------------------------------------

    products_html = ""

    for product in products:

        product_id = product[0]
        name = html.escape(product[1] or "")
        price = html.escape(str(product[2] or ""))
        description = html.escape(product[3] or "")
        subcategory = html.escape(product[5] or "")

        product_icon = get_product_icon(
            product[1],
            product[4],
            product[5]
        )

        products_html += f"""
        <a
            href="/products/{product_id}"
            class="product-card"
        >

            <div class="product-image">
                {product_icon}
            </div>

            <div class="product-info">

                <small>
                    {subcategory or category_name}
                </small>

                <h3>
                    {name}
                </h3>

                <p>
                    {description}
                </p>

                <strong>
                    ₹{price}
                </strong>

            </div>

        </a>
        """

    if not products_html:

        products_html = """
        <div class="empty-box">

            <div class="empty-icon">
                🛍️
            </div>

            <h3>
                No products available
            </h3>

            <p>
                Products added to this category
                will appear here.
            </p>

        </div>
        """

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    {html.escape(category_name)} — Skye Mart
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;

    min-height: 100vh;

    color: #f8fafc;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(79,124,255,.18),
            transparent 30%
        ),
        #070b16;
}}

.container {{
    width: min(
        1200px,
        calc(100% - 24px)
    );

    margin: auto;

    padding: 22px 0 60px;
}}


/* BACK */

.back-btn {{
    display: inline-flex;

    align-items: center;

    gap: 7px;

    padding: 10px 14px;

    margin-bottom: 20px;

    border-radius: 12px;

    color: #cbd5e1;

    text-decoration: none;

    background:
        rgba(255,255,255,.05);

    border:
        1px solid rgba(255,255,255,.09);

    font-size: 12px;
}}

.back-btn:hover {{
    background:
        rgba(79,124,255,.12);

    color: white;
}}


/* HEADER */

.category-header {{
    padding: 32px;

    border-radius: 25px;

    border:
        1px solid rgba(255,255,255,.08);

    background:
        linear-gradient(
            135deg,
            rgba(79,124,255,.14),
            rgba(118,76,255,.08)
        );
}}

.category-icon {{
    font-size: 40px;
}}

.category-header h1 {{
    margin: 10px 0 6px;

    font-size: 32px;
}}

.category-header p {{
    margin: 0;

    color: #71809a;

    font-size: 12px;
}}


/* SUBCATEGORY */

.section-title {{
    margin: 30px 0 14px;

    font-size: 19px;
}}

.subcategories {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(180px, 1fr)
        );

    gap: 12px;
}}

.subcategory-card {{
    position: relative;

    display: block;

    padding: 18px;

    min-height: 105px;

    border-radius: 17px;

    color: white;

    text-decoration: none;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid rgba(255,255,255,.08);

    transition: .22s;
}}

.subcategory-card:hover {{
    transform:
        translateY(-3px);

    border-color:
        rgba(79,124,255,.45);

    background:
        rgba(79,124,255,.10);
}}

.subcategory-icon {{
    font-size: 25px;

    margin-bottom: 12px;
}}

.subcategory-name {{
    font-size: 13px;

    font-weight: 600;
}}

.subcategory-arrow {{
    position: absolute;

    right: 15px;

    bottom: 14px;

    color: #7f9cff;

    font-size: 16px;
}}


/* PRODUCTS */

.products {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fill,
            minmax(210px, 1fr)
        );

    gap: 15px;
}}

.product-card {{
    overflow: hidden;

    color: white;

    text-decoration: none;

    border-radius: 18px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid rgba(255,255,255,.08);

    transition: .22s;
}}

.product-card:hover {{
    transform:
        translateY(-4px);

    border-color:
        rgba(79,124,255,.40);
}}

.product-image {{
    height: 170px;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        rgba(255,255,255,.035);

    font-size: 55px;
}}

.product-info {{
    padding: 14px;
}}

.product-info small {{
    color: #7f9cff;

    font-size: 10px;
}}

.product-info h3 {{
    margin: 7px 0;

    font-size: 14px;
}}

.product-info p {{
    height: 34px;

    overflow: hidden;

    margin: 0 0 12px;

    color: #71809a;

    font-size: 10px;

    line-height: 1.5;
}}

.product-info strong {{
    font-size: 17px;
}}


/* EMPTY */

.empty-box {{
    grid-column: 1 / -1;

    padding: 60px 20px;

    text-align: center;

    color: #71809a;
}}

.empty-icon {{
    margin-bottom: 10px;

    font-size: 45px;
}}


/* MOBILE */

@media(max-width:600px) {{

    .container {{
        width: calc(100% - 14px);
    }}

    .category-header {{
        padding: 24px;
    }}

    .category-header h1 {{
        font-size: 27px;
    }}

    .subcategories {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .subcategory-card {{
        min-height: 95px;
    }}

    .products {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .product-image {{
        height: 140px;
    }}
}}

</style>

</head>

<body>

<div class="container">

    <a
        href="/"
        class="back-btn"
    >
        ← Back to Skye Mart
    </a>


    <section class="category-header">

        <div class="category-icon">
            {category_icon}
        </div>

        <h1>
            {html.escape(category_name)}
        </h1>

        <p>
            Choose a subcategory to explore
            specific products.
        </p>

    </section>


    <h2 class="section-title">
        Explore {html.escape(category_name)}
    </h2>


    <div class="subcategories">

        {subcategory_html}

    </div>


    <h2 class="section-title">
        All {html.escape(category_name)} Products
    </h2>


    <div class="products">

        {products_html}

    </div>

</div>

</body>

</html>
"""


# =========================================================
# SUBCATEGORY PAGE
# =========================================================

@app.get(
    "/category/{category_slug}/{subcategory_slug}",
    response_class=HTMLResponse
)
def subcategory_page(
    category_slug: str,
    subcategory_slug: str
):

    if category_slug not in CATEGORY_MAP:
        return RedirectResponse("/", status_code=303)

    data = CATEGORY_MAP[category_slug]

    category_name = data["name"]
    category_icon = data["icon"]
    subcategories = data["subcategories"]

    # Get subcategory data
    if subcategory_slug not in subcategories:
        return RedirectResponse(
            f"/category/{category_slug}",
            status_code=303
        )

    subcategory_data = subcategories[subcategory_slug]

    if isinstance(subcategory_data, dict):
        subcategory_name = subcategory_data["name"]
        subcategory_icon = subcategory_data.get(
            "icon",
            category_icon
        )
    else:
        subcategory_name = subcategory_data
        subcategory_icon = category_icon

    db = get_db()

    products = db.execute("""
        SELECT
            id,
            name,
            price,
            description,
            category,
            subcategory,
            image_url,
            stock
        FROM products
        WHERE LOWER(TRIM(category))
        = LOWER(TRIM(?))
        ORDER BY id DESC
    """, (category_name,)).fetchall()

    db.close()

    # Automatically detect subcategory for old products
    filtered_products = []

    for product in products:

        detected_subcategory = get_product_subcategory(
            product[1],
            product[4]
        )

        saved_subcategory = product[5] or ""

        final_subcategory = (
            saved_subcategory
            if saved_subcategory
            else detected_subcategory
        )

        if final_subcategory.lower().strip() == subcategory_name.lower().strip():

            filtered_products.append(
                (
                    product[0],
                    product[1],
                    product[2],
                    product[3],
                    product[4],
                    final_subcategory,
                    product[6],
                    product[7]
                )
            )

    products = filtered_products

    products_html = ""

    for product in products:

        product_id = product[0]

        name = html.escape(
            product[1] or ""
        )

        price = html.escape(
            str(product[2] or "")
        )

        description = html.escape(
            product[3] or ""
        )

        image_url = html.escape(
            product[6] or ""
        )

        try:
            stock = int(product[7] or 0)
        except (ValueError, TypeError):
            stock = 0

        product_icon = get_product_icon(
            product[1],
            product[4],
            product[5]
        )

        if image_url:
            image_display = f"""
            <img
                src="{image_url}"
                alt="{name}"
                style="
                    width:100%;
                    height:100%;
                    object-fit:contain;
                "
                onerror="
                    this.style.display='none';
                    this.nextElementSibling.style.display='flex';
                "
            >
            <div style="
                display:none;
                width:100%;
                height:100%;
                align-items:center;
                justify-content:center;
                font-size:55px;
            ">
                {product_icon}
            </div>
            """
        else:
            image_display = f"""
            <div style="
                width:100%;
                height:100%;
                display:flex;
                align-items:center;
                justify-content:center;
                font-size:55px;
            ">
                {product_icon}
            </div>
            """

        stock_warning = ""

        if stock <= 0:
            stock_warning = """
            <div style="
                color:#f87171;
                font-size:11px;
                font-weight:700;
                margin-top:8px;
            ">
                Out of stock
            </div>
            """
        elif stock < 10:
            stock_warning = f"""
            <div style="
                color:#fbbf24;
                font-size:11px;
                font-weight:700;
                margin-top:8px;
            ">
                Only {stock} left
            </div>
            """

        products_html += f"""
        <a
            href="/products/{product_id}"
            class="product-card"
        >

            <div class="product-image">
                {image_display}
            </div>

            <div class="product-info">

                <small>
                    {html.escape(subcategory_name)}
                </small>

                <h3>
                    {name}
                </h3>

                <p>
                    {description}
                </p>

                <strong>
                    ₹{price}
                </strong>

                {stock_warning}

            </div>

        </a>
        """

    if not products_html:

        products_html = f"""
        <div class="empty-box">

            <div class="empty-icon">
                🔍
            </div>

            <h3>
                No products available
            </h3>

            <p>
                No products have been added to
                {html.escape(subcategory_name)}
                yet.
            </p>

        </div>
        """

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    {html.escape(subcategory_name)}
    — Skye Mart
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;

    min-height: 100vh;

    color: #f8fafc;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(79,124,255,.18),
            transparent 30%
        ),
        #070b16;
}}

.container {{
    width: min(
        1200px,
        calc(100% - 24px)
    );

    margin: auto;

    padding: 22px 0 60px;
}}

.back-btn {{
    display: inline-flex;

    padding: 10px 14px;

    margin-bottom: 20px;

    border-radius: 12px;

    color: #cbd5e1;

    text-decoration: none;

    background:
        rgba(255,255,255,.05);

    border:
        1px solid rgba(255,255,255,.09);

    font-size: 12px;
}}

.page-header {{
    padding: 28px;

    margin-bottom: 25px;

    border-radius: 23px;

    background:
        linear-gradient(
            135deg,
            rgba(79,124,255,.14),
            rgba(118,76,255,.08)
        );

    border:
        1px solid rgba(255,255,255,.08);
}}

.page-header .icon {{
    font-size: 38px;
}}

.page-header h1 {{
    margin: 10px 0 5px;

    font-size: 29px;
}}

.page-header p {{
    margin: 0;

    color: #71809a;

    font-size: 12px;
}}

.products {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fill,
            minmax(210px, 1fr)
        );

    gap: 15px;
}}

.product-card {{
    overflow: hidden;

    color: white;

    text-decoration: none;

    border-radius: 18px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid rgba(255,255,255,.08);

    transition: .22s;
}}

.product-card:hover {{
    transform:
        translateY(-4px);

    border-color:
        rgba(79,124,255,.4);
}}

.product-image {{
    height: 180px;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        rgba(255,255,255,.035);

    font-size: 55px;
}}

.product-info {{
    padding: 15px;
}}

.product-info small {{
    color: #7f9cff;

    font-size: 10px;
}}

.product-info h3 {{
    margin: 7px 0;

    font-size: 14px;
}}

.product-info p {{
    height: 34px;

    overflow: hidden;

    margin: 0 0 12px;

    color: #71809a;

    font-size: 10px;
}}

.product-info strong {{
    font-size: 17px;
}}

.empty-box {{
    grid-column: 1 / -1;

    padding: 60px 20px;

    text-align: center;

    color: #71809a;
}}

.empty-icon {{
    font-size: 45px;
}}

@media(max-width:600px) {{

    .container {{
        width: calc(100% - 14px);
    }}

    .products {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .product-image {{
        height: 140px;
    }}
}}

</style>

</head>

<body>

<div class="container">

    <a
        href="/category/{category_slug}"
        class="back-btn"
    >
        ← Back to {html.escape(category_name)}
    </a>


    <section class="page-header">

        <div class="icon">
            {subcategory_icon}
        </div>

        <h1>
            {html.escape(subcategory_name)}
        </h1>

        <p>
            Products in
            {html.escape(category_name)}
            → {html.escape(subcategory_name)}
        </p>

    </section>


    <div class="products">

        {products_html}

    </div>

</div>

</body>

</html>
"""


# =========================================================
# PRODUCT DETAILS
# =========================================================

@app.get("/products/{product_id}", response_class=HTMLResponse)
def product_details(product_id: int):

    products = get_products()

    product = next(
        (
            p for p in products
            if p[0] == product_id
        ),
        None
    )

    if not product:
        return page_shell(
            "Product Not Found",
            """
            <div class="empty">
                <h2>Product Not Found</h2>
                <p>This product is no longer available.</p>
                <a class="btn" href="/">
                    ← Back to Skye Mart
                </a>
            </div>
            """
        )

    product_id = product[0]
    name = html.escape(product[1] or "")
    price = html.escape(str(product[2] or ""))
    description = html.escape(product[3] or "")
    image_url = html.escape(product[6] or "")

    try:
        stock = int(product[7] or 0)
    except (ValueError, TypeError):
        stock = 0

    if stock <= 0:
        stock_text = "Out of stock"
        stock_color = "#f87171"
    elif stock < 10:
        stock_text = f"Only {stock} left"
        stock_color = "#fbbf24"
    else:
        stock_text = f"{stock} in stock"
        stock_color = "#86efac"

    # Product icon
    icon = get_product_icon(
        product[1],
        "",
        ""
    )

    # Image display
    if image_url:
        image_display = f"""
        <div class="product-detail-image">
            <img
                src="{image_url}"
                alt="{name}"
                style="
                    width:100%;
                    height:100%;
                    object-fit:contain;
                "
                onerror="
                    this.style.display='none';
                    this.nextElementSibling.style.display='flex';
                "
            >
            <div
                style="
                    display:none;
                    width:100%;
                    height:100%;
                    align-items:center;
                    justify-content:center;
                    font-size:120px;
                "
            >
                {icon}
            </div>
        </div>
        """
    else:
        image_display = f"""
        <div class="product-detail-image">
            {icon}
        </div>
        """

    content = f"""
    <style>

    .product-detail {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 30px;
        padding: 28px;
        border-radius: 24px;
        background: rgba(255,255,255,.045);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .product-detail-image {{
        min-height: 420px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 20px;
        background: rgba(255,255,255,.035);
        font-size: 120px;
        flex-direction: column;
        width:100%;
        height:100%;
    }}

    .product-main-image {{
        width: 100%;
        height: 100%;
        min-height: 350px;
        max-height: 520px;
        object-fit: contain;
        display: block;
        border-radius: 22px;
    }}

    .image-fallback {{
        min-height: 350px;
        width: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        color: #64748b;
        font-size: 14px;
    }}

    .image-fallback span:first-child {{
        font-size: 50px;
    }}

    .product-detail-info {{
        padding: 15px 5px;
    }}

    .product-detail-info h2 {{
        margin: 0 0 12px;
        font-size: 32px;
    }}

    .product-detail-price {{
        margin: 15px 0;
        font-size: 28px;
        font-weight: 800;
    }}

    .product-detail-description {{
        margin: 20px 0;
        color: #94a3b8;
        line-height: 1.7;
    }}

    .stock {{
        display: inline-flex;
        padding: 7px 12px;
        border-radius: 999px;
        font-size: 12px;
    }}

    .quantity-box {{
        display: flex;
        align-items: center;
        gap: 15px;
        margin: 22px 0;
    }}

    .quantity-box button {{
        width: 38px;
        height: 38px;
        border: 0;
        border-radius: 10px;
        cursor: pointer;
        color: white;
        background: #27304a;
        font-size: 20px;
    }}

    #quantity {{
        min-width: 25px;
        text-align: center;
        font-weight: 700;
    }}

    .cart-actions {{
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
    }}

    .cart-btn {{
        border: 0;
        cursor: pointer;
        padding: 14px 20px;
        border-radius: 13px;
        color: white;
        background: linear-gradient(
            135deg,
            #5865f2,
            #7654ff
        );
        font-weight: 700;
    }}

    .buy-btn {{
        border: 1px solid rgba(255,255,255,.12);
        cursor: pointer;
        padding: 14px 20px;
        border-radius: 13px;
        color: white;
        background: rgba(255,255,255,.06);
        font-weight: 700;
    }}

    .cart-message {{
        margin-top: 15px;
        color: #86efac;
        font-size: 13px;
    }}

    @media(max-width:700px) {{

        .product-detail {{
            grid-template-columns: 1fr;
            padding: 18px;
        }}

        .product-detail-image {{
            min-height: 280px;
            font-size: 90px;
        }}

        .product-detail-info h2 {{
            font-size: 25px;
        }}

    }}

    </style>


    <div class="product-detail">

        {image_display}

        <div class="product-detail-info">

            <h2>
                {name}
            </h2>

            <div class="stock" style="color:{stock_color};">
                {stock_text}
            </div>

            <div class="product-detail-price">
                ₹{price}
            </div>

            <div class="product-detail-description">
                {description or "No description available for this product."}
            </div>


            <div class="quantity-box">

                <button onclick="changeQuantity(-1)">
                    −
                </button>

                <span id="quantity">
                    1
                </span>

                <button onclick="changeQuantity(1)">
                    +
                </button>

            </div>


            <div class="cart-actions">

                <button
                    class="cart-btn"
                    onclick="addToCart()"
                >
                    🛒 Add to Cart
                </button>

                <button
                    class="buy-btn"
                    onclick="buyNow()"
                >
                    ⚡ Buy Now
                </button>

            </div>


            <div
                id="cartMessage"
                class="cart-message"
            ></div>

        </div>

    </div>


    <script>

    let quantity = 1;


    function changeQuantity(value) {{

        quantity += value;

        if (quantity < 1) {{
            quantity = 1;
        }}

        if (quantity > 99) {{
            quantity = 99;
        }}

        document
            .getElementById("quantity")
            .innerText = quantity;
    }}


    function getCart() {{

        try {{
            return JSON.parse(
                localStorage.getItem("skye_cart")
            ) || {{}};

        }} catch {{
            return {{}};
        }}
    }}


    function saveCart(cart) {{

        localStorage.setItem(
            "skye_cart",
            JSON.stringify(cart)
        );
    }}


    function addToCart() {{

        const cart = getCart();

        const id = "{product_id}";

        cart[id] =
            (cart[id] || 0) + quantity;

        saveCart(cart);

        document
            .getElementById("cartMessage")
            .innerText =
                "✓ Product added to cart";

        quantity = 1;

        document
            .getElementById("quantity")
            .innerText = "1";
    }}


    function buyNow() {{

        addToCart();

        setTimeout(function() {{
            window.location.href = "/cart";
        }}, 200);

    }}

    </script>
    """

    return page_shell(
        f"🛍️ {name}",
        content
    )


# =========================================================
# CART PAGE
# =========================================================

@app.get("/cart", response_class=HTMLResponse)
def cart_page():

    products = get_products()

    product_data = []

    for product in products:

        product_data.append({
            "id": product[0],
            "name": product[1] or "",
            "price": product[2] or "0",
            "description": product[3] or ""
        })

    products_json = json.dumps(
        product_data
    )

    content = f"""

    <style>

    .cart-container {{
        max-width: 1000px;
        margin: auto;
    }}

    .cart-item {{
        display: grid;
        grid-template-columns: 70px 1fr auto;
        gap: 18px;
        align-items: center;
        padding: 16px;
        margin-bottom: 12px;
        border-radius: 17px;
        background: rgba(255,255,255,.045);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .cart-icon {{
        width: 65px;
        height: 65px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 14px;
        background: rgba(255,255,255,.05);
        font-size: 30px;
    }}

    .cart-name {{
        font-weight: 700;
    }}

    .cart-price {{
        margin-top: 5px;
        color: #8da2ff;
        font-size: 13px;
    }}

    .cart-quantity {{
        display: flex;
        align-items: center;
        gap: 9px;
    }}

    .cart-quantity button {{
        width: 30px;
        height: 30px;
        border: 0;
        border-radius: 8px;
        color: white;
        background: #293149;
        cursor: pointer;
    }}

    .cart-remove {{
        margin-top: 7px;
        border: 0;
        background: transparent;
        color: #f87171;
        cursor: pointer;
        font-size: 11px;
    }}

    .cart-summary {{
        margin-top: 25px;
        padding: 22px;
        border-radius: 20px;
        background: rgba(255,255,255,.045);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .summary-row {{
        display: flex;
        justify-content: space-between;
        margin: 10px 0;
        color: #94a3b8;
    }}

    .summary-total {{
        display: flex;
        justify-content: space-between;
        padding-top: 15px;
        margin-top: 15px;
        border-top: 1px solid rgba(255,255,255,.08);
        font-size: 20px;
        font-weight: 800;
        color: white;
    }}

    .checkout-btn {{
        width: 100%;
        margin-top: 18px;
        padding: 15px;
        border: 0;
        border-radius: 13px;
        cursor: pointer;
        color: white;
        background: linear-gradient(
            135deg,
            #5865f2,
            #7654ff
        );
        font-weight: 700;
    }}

    .empty-cart {{
        padding: 70px 20px;
        text-align: center;
        color: #94a3b8;
    }}

    .empty-cart-icon {{
        font-size: 55px;
    }}

    @media(max-width:600px) {{

        .cart-item {{
            grid-template-columns: 55px 1fr;
        }}

        .cart-quantity {{
            grid-column: 1 / -1;
        }}

    }}

    </style>


    <div class="cart-container">

        <div
            id="cartItems"
        ></div>

        <div
            id="cartSummary"
        ></div>

    </div>


    <script>

    const PRODUCTS =
        {products_json};


    function getCart() {{

        try {{
            return JSON.parse(
                localStorage.getItem("skye_cart")
            ) || {{}};

        }} catch {{
            return {{}};
        }}
    }}


    function saveCart(cart) {{

        localStorage.setItem(
            "skye_cart",
            JSON.stringify(cart)
        );

    }}


    function iconFor(name) {{

        const text =
            name.toLowerCase();

        if (
            text.includes("iphone") ||
            text.includes("phone") ||
            text.includes("mobile") ||
            text.includes("galaxy")
        ) return "📱";

        if (
            text.includes("laptop") ||
            text.includes("macbook")
        ) return "💻";

        if (
            text.includes("headphone") ||
            text.includes("earbuds") ||
            text.includes("airpods")
        ) return "🎧";

        if (
            text.includes("watch") ||
            text.includes("smartwatch")
        ) return "⌚";

        if (
            text.includes("tv") ||
            text.includes("television")
        ) return "📺";

        if (
            text.includes("shoe") ||
            text.includes("sneaker")
        ) return "👟";

        if (
            text.includes("shirt") ||
            text.includes("jeans") ||
            text.includes("dress")
        ) return "👕";

        if (
            text.includes("book")
        ) return "📚";

        if (
            text.includes("toy")
        ) return "🧸";

        if (
            text.includes("game") ||
            text.includes("playstation") ||
            text.includes("xbox")
        ) return "🎮";

        return "📦";
    }}


    function numberPrice(value) {{

        const n =
            parseFloat(
                String(value)
                    .replace(/[^0-9.]/g, "")
            );

        return isNaN(n) ? 0 : n;

    }}


    function renderCart() {{

        const cart = getCart();

        const container =
            document.getElementById(
                "cartItems"
            );

        const summary =
            document.getElementById(
                "cartSummary"
            );

        let total = 0;

        let count = 0;

        let html = "";


        PRODUCTS.forEach(function(product) {{

            const qty =
                Number(cart[product.id] || 0);

            if (qty <= 0) return;

            const price =
                numberPrice(product.price);

            const itemTotal =
                price * qty;

            total += itemTotal;

            count += qty;


            html += `
                <div class="cart-item">

                    <div class="cart-icon">
                        ${{iconFor(product.name)}}
                    </div>

                    <div>

                        <div class="cart-name">
                            ${{product.name}}
                        </div>

                        <div class="cart-price">
                            ₹${{price.toLocaleString("en-IN")}}
                        </div>

                        <button
                            class="cart-remove"
                            onclick="removeItem(${{product.id}})"
                        >
                            Remove
                        </button>

                    </div>

                    <div class="cart-quantity">

                        <button
                            onclick="changeItem(
                                ${{product.id}},
                                -1
                            )"
                        >
                            −
                        </button>

                        <b>
                            ${{qty}}
                        </b>

                        <button
                            onclick="changeItem(
                                ${{product.id}},
                                1
                            )"
                        >
                            +
                        </button>

                    </div>

                </div>
            `;
        }});


        if (!html) {{

            container.innerHTML = `
                <div class="empty-cart">

                    <div class="empty-cart-icon">
                        🛒
                    </div>

                    <h2>
                        Your cart is empty
                    </h2>

                    <p>
                        Add some products to
                        continue shopping.
                    </p>

                    <a
                        class="btn"
                        href="/"
                    >
                        Continue Shopping
                    </a>

                </div>
            `;

            summary.innerHTML = "";

            return;
        }}


        container.innerHTML = html;


        summary.innerHTML = `

            <div class="cart-summary">

                <div class="summary-row">
                    <span>
                        Items
                    </span>

                    <span>
                        ${{count}}
                    </span>
                </div>


                <div class="summary-row">
                    <span>
                        Subtotal
                    </span>

                    <span>
                        ₹${{total.toLocaleString("en-IN")}}
                    </span>
                </div>


                <div class="summary-row">
                    <span>
                        Delivery
                    </span>

                    <span>
                        Free
                    </span>
                </div>


                <div class="summary-total">

                    <span>
                        Total
                    </span>

                    <span>
                        ₹${{total.toLocaleString("en-IN")}}
                    </span>

                </div>


                <button
                    class="checkout-btn"
                    onclick="checkout()"
                >
                    Proceed to Checkout →
                </button>

            </div>

        `;
    }}


    function changeItem(id, change) {{

        const cart = getCart();

        cart[id] =
            Number(cart[id] || 0) + change;

        if (cart[id] <= 0) {{
            delete cart[id];
        }}

        saveCart(cart);

        renderCart();
    }}


    function removeItem(id) {{

        const cart = getCart();

        delete cart[id];

        saveCart(cart);

        renderCart();
    }}


    function checkout() {{
        window.location.href = "/checkout";
    }}


    renderCart();

    </script>

    """

    return page_shell(
        "🛒 Your Cart",
        content
    )


# =========================================================
# CHECKOUT
# =========================================================

@app.get("/checkout", response_class=HTMLResponse)
def checkout_page():

    products = get_products()

    products_data = []

    for product in products:
        products_data.append({
            "id": product[0],
            "name": product[1] or "",
            "price": str(product[2] or "0")
        })

    products_json = json.dumps(products_data)

    content = f"""
    <style>

    .checkout-wrapper {{
        max-width: 1050px;
        margin: auto;
    }}

    .checkout-grid {{
        display: grid;
        grid-template-columns: 1.4fr .8fr;
        gap: 20px;
    }}

    .checkout-card {{
        padding: 24px;
        border-radius: 20px;
        background: rgba(255,255,255,.045);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .checkout-card h2 {{
        margin-top: 0;
        font-size: 20px;
    }}

    .field {{
        margin-bottom: 15px;
    }}

    .field label {{
        display: block;
        margin-bottom: 7px;
        color: #94a3b8;
        font-size: 12px;
    }}

    .field input,
    .field textarea {{
        width: 100%;
        padding: 13px 14px;
        border-radius: 11px;
        outline: none;
        color: white;
        background: rgba(0,0,0,.18);
        border: 1px solid rgba(255,255,255,.10);
    }}

    .field textarea {{
        min-height: 90px;
        resize: vertical;
    }}

    .payment-options {{
        display: grid;
        gap: 10px;
        margin-top: 15px;
    }}

    .payment-option {{
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px;
        border-radius: 13px;
        cursor: pointer;
        background: rgba(255,255,255,.035);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .payment-option:hover {{
        border-color: rgba(79,124,255,.45);
    }}

    .payment-option input {{
        accent-color: #5865f2;
    }}

    .payment-icon {{
        font-size: 22px;
    }}

    .payment-name {{
        font-weight: 600;
        font-size: 13px;
    }}

    .payment-description {{
        margin-top: 3px;
        color: #71809a;
        font-size: 10px;
    }}

    .order-item {{
        display: flex;
        justify-content: space-between;
        gap: 12px;
        padding: 12px 0;
        border-bottom: 1px solid rgba(255,255,255,.06);
        font-size: 12px;
    }}

    .order-item-name {{
        color: #cbd5e1;
    }}

    .order-item-price {{
        white-space: nowrap;
        font-weight: 600;
    }}

    .summary-row {{
        display: flex;
        justify-content: space-between;
        margin-top: 13px;
        color: #94a3b8;
        font-size: 13px;
    }}

    .summary-total {{
        display: flex;
        justify-content: space-between;
        margin-top: 18px;
        padding-top: 18px;
        border-top: 1px solid rgba(255,255,255,.10);
        font-size: 20px;
        font-weight: 800;
    }}

    .place-order {{
        width: 100%;
        margin-top: 20px;
        padding: 15px;
        border: 0;
        border-radius: 13px;
        cursor: pointer;
        color: white;
        background: linear-gradient(
            135deg,
            #5865f2,
            #7654ff
        );
        font-weight: 700;
    }}

    .place-order:hover {{
        opacity: .92;
    }}

    .security-note {{
        margin-top: 14px;
        color: #71809a;
        text-align: center;
        font-size: 10px;
    }}

    .checkout-error {{
        display: none;
        margin-bottom: 15px;
        padding: 11px;
        border-radius: 10px;
        color: #fca5a5;
        background: rgba(239,68,68,.10);
        border: 1px solid rgba(239,68,68,.15);
        font-size: 12px;
    }}

    @media(max-width:750px) {{

        .checkout-grid {{
            grid-template-columns: 1fr;
        }}

    }}

    </style>


    <div class="checkout-wrapper">

        <div style="margin-bottom:18px;">

            <a
                class="btn"
                href="/cart"
            >
                ← Back to Cart
            </a>

        </div>


        <div class="checkout-grid">


            <!-- CUSTOMER DETAILS -->

            <section class="checkout-card">

                <h2>
                    📦 Delivery Details
                </h2>

                <div
                    id="checkoutError"
                    class="checkout-error"
                ></div>


                <form
                    id="checkoutForm"
                    onsubmit="placeOrder(event)"
                >

                    <div class="field">

                        <label>
                            Full Name
                        </label>

                        <input
                            id="customerName"
                            type="text"
                            placeholder="Enter your full name"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Mobile Number
                        </label>

                        <input
                            id="customerPhone"
                            type="tel"
                            maxlength="10"
                            pattern="[0-9]{{10}}"
                            placeholder="10-digit mobile number"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Delivery Address
                        </label>

                        <textarea
                            id="customerAddress"
                            placeholder="House no., street, area..."
                            required
                        ></textarea>

                    </div>


                    <div class="field">

                        <label>
                            City
                        </label>

                        <input
                            id="customerCity"
                            type="text"
                            placeholder="City"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Pincode
                        </label>

                        <input
                            id="customerPincode"
                            type="text"
                            maxlength="6"
                            pattern="[0-9]{{6}}"
                            placeholder="6-digit pincode"
                            required
                        >

                    </div>


                    <h2 style="margin-top:28px;">
                        💳 Payment Method
                    </h2>


                    <div class="payment-options">


                        <label class="payment-option">

                            <input
                                type="radio"
                                name="payment"
                                value="UPI"
                                checked
                            >

                            <span class="payment-icon">
                                📲
                            </span>

                            <div>

                                <div class="payment-name">
                                    UPI
                                </div>

                                <div class="payment-description">
                                    Google Pay, PhonePe, Paytm etc.
                                </div>

                            </div>

                        </label>


                        <label class="payment-option">

                            <input
                                type="radio"
                                name="payment"
                                value="COD"
                            >

                            <span class="payment-icon">
                                💵
                            </span>

                            <div>

                                <div class="payment-name">
                                    Cash on Delivery
                                </div>

                                <div class="payment-description">
                                    Pay when your order arrives.
                                </div>

                            </div>

                        </label>


                        <label class="payment-option">

                            <input
                                type="radio"
                                name="payment"
                                value="CARD"
                            >

                            <span class="payment-icon">
                                💳
                            </span>

                            <div>

                                <div class="payment-name">
                                    Credit / Debit Card
                                </div>

                                <div class="payment-description">
                                    Demo payment for testing.
                                </div>

                            </div>

                        </label>


                        <label class="payment-option">

                            <input
                                type="radio"
                                name="payment"
                                value="EMI"
                            >

                            <span class="payment-icon">
                                🏦
                            </span>

                            <div>

                                <div class="payment-name">
                                    EMI
                                </div>

                                <div class="payment-description">
                                    EMI option will be connected later.
                                </div>

                            </div>

                        </label>

                    </div>


                    <div
                        id="paymentDetailsBox"
                        style="
                            margin-top:15px;
                            padding:16px;
                            border-radius:14px;
                            background:rgba(79,124,255,.06);
                            border:1px solid rgba(79,124,255,.12);
                        "
                    >

                        <!-- UPI -->
                        <div
                            id="upiDetails"
                            class="payment-details"
                            style="display:none;"
                        >

                            <label>UPI ID</label>

                            <input
                                id="upiId"
                                type="text"
                                maxlength="100"
                                placeholder="example@upi"
                            >

                            <label style="margin-top:12px;">UTR / Transaction ID</label>

                            <input
                                id="paymentUtr"
                                type="text"
                                maxlength="30"
                                placeholder="Enter UTR (optional)"
                            >

                        </div>


                        <!-- CARD -->
                        <div
                            id="cardDetails"
                            class="payment-details"
                            style="display:none;"
                        >

                            <label>Cardholder Name</label>

                            <input
                                id="cardHolderName"
                                type="text"
                                placeholder="Name on card"
                            >

                            <label style="margin-top:12px;">Last 4 Digits</label>

                            <input
                                id="cardLast4"
                                type="text"
                                maxlength="4"
                                pattern="[0-9]{{4}}"
                                placeholder="1234"
                            >

                            <p style="margin-top:10px;color:#71809a;font-size:11px;">
                                🔒 Full card details are not stored for security.
                            </p>

                        </div>


                        <!-- EMI -->
                        <div
                            id="emiDetails"
                            class="payment-details"
                            style="display:none;"
                        >

                            <label>EMI Provider</label>

                            <select id="emiProvider">

                                <option value="">
                                    Select EMI provider
                                </option>

                                <option value="Bank EMI">
                                    Bank EMI
                                </option>

                                <option value="Card EMI">
                                    Card EMI
                                </option>

                            </select>

                            <label style="margin-top:12px;">
                                EMI Tenure
                            </label>

                            <select id="emiTenure">

                                <option value="">
                                    Select tenure
                                </option>

                                <option value="3 Months">
                                    3 Months
                                </option>

                                <option value="6 Months">
                                    6 Months
                                </option>

                                <option value="9 Months">
                                    9 Months
                                </option>

                                <option value="12 Months">
                                    12 Months
                                </option>

                            </select>

                            <label style="margin-top:12px;">
                                EMI Reference
                            </label>

                            <input
                                id="emiReference"
                                type="text"
                                placeholder="Optional reference"
                            >

                        </div>

                    </div>


                    <button
                        class="place-order"
                        type="submit"
                    >
                        Place Order →
                    </button>


                    <div class="security-note">
                        🔒 Demo checkout — no real payment is processed.
                    </div>

                </form>

            </section>



            <!-- ORDER SUMMARY -->

            <section class="checkout-card">

                <h2>
                    🛒 Order Summary
                </h2>

                <div id="orderItems">
                </div>


                <div class="summary-row">

                    <span>
                        Subtotal
                    </span>

                    <span id="subtotal">
                        ₹0
                    </span>

                </div>


                <div class="summary-row">

                    <span>
                        Delivery
                    </span>

                    <span>
                        Free
                    </span>

                </div>


                <div class="summary-total">

                    <span>
                        Total
                    </span>

                    <span id="total">
                        ₹0
                    </span>

                </div>

            </section>

        </div>

    </div>


    <script>

    const PRODUCTS =
        {products_json};


    let checkoutTotal = 0;


    function getCart() {{

        try {{

            return JSON.parse(
                localStorage.getItem("skye_cart")
            ) || {{}};

        }} catch {{

            return {{}};

        }}

    }}


    function priceNumber(value) {{

        const number =
            parseFloat(
                String(value)
                    .replace(/[^0-9.]/g, "")
            );

        return isNaN(number)
            ? 0
            : number;

    }}


    function renderOrder() {{

        const cart = getCart();

        const container =
            document.getElementById(
                "orderItems"
            );

        let html = "";

        let total = 0;


        PRODUCTS.forEach(function(product) {{

            const quantity =
                Number(
                    cart[product.id] || 0
                );

            if (quantity <= 0) return;


            const price =
                priceNumber(product.price);


            const itemTotal =
                price * quantity;


            total += itemTotal;


            html += `

                <div class="order-item">

                    <div class="order-item-name">

                        ${{product.name}}

                        <span style="color:#71809a;">
                            × ${{quantity}}
                        </span>

                    </div>

                    <div class="order-item-price">
                        ₹${{itemTotal.toLocaleString("en-IN")}}
                    </div>

                </div>

            `;

        }});


        checkoutTotal = total;


        if (!html) {{

            container.innerHTML = `
                <p style="color:#94a3b8;">
                    Your cart is empty.
                </p>
            `;

        }} else {{

            container.innerHTML = html;

        }}


        document
            .getElementById("subtotal")
            .innerText =
                "₹" +
                total.toLocaleString("en-IN");


        document
            .getElementById("total")
            .innerText =
                "₹" +
                total.toLocaleString("en-IN");

    }}


    function showError(message) {{

        const error =
            document.getElementById(
                "checkoutError"
            );

        error.innerText = message;

        error.style.display = "block";

        window.scrollTo({{
            top: 0,
            behavior: "smooth"
        }});

    }}


    function updatePaymentUI() {{

        const selected =
            document.querySelector(
                'input[name="payment"]:checked'
            );

        const upi =
            document.getElementById("upiDetails");

        const card =
            document.getElementById("cardDetails");

        const emi =
            document.getElementById("emiDetails");

        if (!selected) {{
            return;
        }}

        upi.style.display = "none";
        card.style.display = "none";
        emi.style.display = "none";

        if (selected.value === "UPI") {{

            upi.style.display = "block";

        }} else if (selected.value === "CARD") {{

            card.style.display = "block";

        }} else if (selected.value === "EMI") {{

            emi.style.display = "block";
        }}
    }}


    document
        .querySelectorAll(
            'input[name="payment"]'
        )
        .forEach(function(input) {{

            input.addEventListener(
                "change",
                updatePaymentUI
            );

        }});


    updatePaymentUI();


    async function placeOrder(event) {{

        event.preventDefault();

        const cart = getCart();

        if (Object.keys(cart).length === 0) {{

            showError("Your cart is empty.");

            return;
        }}


        const name =
            document
                .getElementById("customerName")
                .value
                .trim();

        const phone =
            document
                .getElementById("customerPhone")
                .value
                .trim();

        const address =
            document
                .getElementById("customerAddress")
                .value
                .trim();

        const city =
            document
                .getElementById("customerCity")
                .value
                .trim();

        const pincode =
            document
                .getElementById("customerPincode")
                .value
                .trim();

        const payment =
            document
                .querySelector(
                    'input[name="payment"]:checked'
                )
                .value;

        const upiId =
            document
                .getElementById("upiId")
                .value
                .trim();

        const utr =
            document
                .getElementById("paymentUtr")
                .value
                .trim();

        const cardHolderName =
            document
                .getElementById("cardHolderName")
                .value
                .trim();

        const cardLast4 =
            document
                .getElementById("cardLast4")
                .value
                .trim();

        const emiProvider =
            document
                .getElementById("emiProvider")
                .value;

        const emiTenure =
            document
                .getElementById("emiTenure")
                .value;

        const emiReference =
            document
                .getElementById("emiReference")
                .value
                .trim();


        if (!/^[0-9]{{10}}$/.test(phone)) {{

            showError(
                "Please enter a valid 10-digit mobile number."
            );

            return;
        }}


        if (!/^[0-9]{{6}}$/.test(pincode)) {{

            showError(
                "Please enter a valid 6-digit pincode."
            );

            return;
        }}


        if (payment === "UPI") {{

            if (!upiId) {{

                showError(
                    "Please enter your UPI ID."
                );

                return;
            }}


        }} else if (payment === "CARD") {{

            if (!cardHolderName) {{

                showError(
                    "Please enter cardholder name."
                );

                return;
            }}

            if (!/^\d{{4}}$/.test(cardLast4)) {{

                showError(
                    "Please enter the last 4 digits of the card."
                );

                return;
            }}


        }} else if (payment === "EMI") {{

            if (!emiProvider || !emiTenure) {{

                showError(
                    "Please select EMI provider and tenure."
                );

                return;
            }}

        }}


        /*
            Create readable product list
        */

        const selectedProducts = [];

        PRODUCTS.forEach(function(product) {{

            const quantity =
                Number(cart[product.id] || 0);

            if (quantity > 0) {{

                selectedProducts.push(
                    product.name +
                    " × " +
                    quantity
                );
            }}

        }});


        const productName =
            selectedProducts.join(", ");


        const orderId =
            "SKY" +
            Date.now()
                .toString()
                .slice(-8);


        /*
            Save order to backend database
        */

        try {{

            const response =
                await fetch(
                    "/checkout/save-order",
                    {{
                        method: "POST",

                        headers: {{
                            "Content-Type":
                                "application/json"
                        }},

                        body: JSON.stringify({{

                            order_number:
                                orderId,

                            customer_name:
                                name,

                            product_name:
                                productName,

                            price:
                                String(checkoutTotal),

                            phone:
                                phone,

                            address:
                                address,

                            city:
                                city,

                            pincode:
                                pincode,

                            payment:
                                payment,

                            upi_id:
                                upiId,

                            utr:
                                utr,

                            card_holder_name:
                                cardHolderName,

                            card_last4:
                                cardLast4,

                            emi_provider:
                                emiProvider,

                            emi_tenure:
                                emiTenure,

                            emi_reference:
                                emiReference,

                            cart:
                                cart

                        }})
                    }}
                );


            const data =
                await response.json();


            if (!data.success) {{

                showError(
                    data.message ||
                    "Unable to place order."
                );

                return;
            }}


            /*
                Save extra customer information
                locally for this demo
            */

            const order = {{

                orderId: orderId,

                customer: {{

                    name: name,

                    phone: phone,

                    address: address,

                    city: city,

                    pincode: pincode

                }},

                payment: payment,

                total: checkoutTotal,

                cart: cart,

                createdAt:
                    new Date().toISOString(),

                status:
                    "Confirmed"

            }};


            localStorage.setItem(
                "skye_last_order",
                JSON.stringify(order)
            );


            /*
                Empty cart
            */

            localStorage.removeItem(
                "skye_cart"
            );


            /*
                Go to success page
            */

            window.location.href =
                "/order-success?order=" +
                encodeURIComponent(orderId);


        }} catch (error) {{

            console.error(error);

            showError(
                "Unable to connect to the server. Please try again."
            );

        }}

    }}


    renderOrder();

    </script>

    """

    return page_shell(
        "🛒 Checkout — Skye Mart",
        content
    )


# =========================================================
# SAVE CUSTOMER CHECKOUT ORDER
# =========================================================

@app.post("/checkout/save-order")
def save_checkout_order(order: CheckoutOrder):

    db = get_db()

    order_number = order.order_number.strip().upper()
    customer_name = order.customer_name.strip()
    product_name = order.product_name.strip()

    price = clean_price(order.price)

    phone = order.phone.strip()
    address = order.address.strip()
    city = order.city.strip()
    pincode = order.pincode.strip()

    payment_method = order.payment.strip().upper()
    payment_status = "Pending"

    upi_id = order.upi_id.strip()
    utr = order.utr.strip()

    card_holder_name = order.card_holder_name.strip()
    card_last4 = order.card_last4.strip()

    emi_provider = order.emi_provider.strip()
    emi_tenure = order.emi_tenure.strip()
    emi_reference = order.emi_reference.strip()

    created_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ---------------------------------------------
    # CONVERT CART TEXT INTO PRODUCT + QUANTITY
    # ---------------------------------------------

    items = []

    cart = order.cart or {}

    for product_id_str, quantity in cart.items():

        try:
            product_id = int(product_id_str)
            quantity = int(quantity)
        except (ValueError, TypeError):
            continue

        if quantity <= 0:
            continue

        # Ensure product exists
        product = db.execute(
            """
            SELECT
                id,
                name,
                price,
                stock
            FROM products
            WHERE id = ?
            LIMIT 1
            """,
            (product_id,)
        ).fetchone()

        if not product:
            return {
                "success": False,
                "message":
                    f"Product not found: {product_name}"
            }

        items.append(
            (
                product[0],
                product[1],
                quantity
            )
        )

    if not items:
        return {
            "success": False,
            "message": "No product selected."
        }

    # ---------------------------------------------
    # CHECK STOCK
    # ---------------------------------------------

    checked_products = []

    for product_id, product_name, quantity in items:

        product = db.execute(
            """
            SELECT
                id,
                name,
                price,
                stock
            FROM products
            WHERE id = ?
            LIMIT 1
            """,
            (product_id,)
        ).fetchone()

        if not product:
            return {
                "success": False,
                "message":
                    f"Product not found: {product_name}"
            }

        try:
            stock = int(product[3] or 0)
        except (ValueError, TypeError):
            stock = 0

        if stock < quantity:
            return {
                "success": False,
                "message":
                    f"Not enough stock for {product[1]}. "
                    f"Available: {stock}"
            }

        checked_products.append(
            (
                product,
                quantity
            )
        )

    # Build product text for order
    product_text = ", ".join(
        f"{product[1]} × {quantity}"
        for product, quantity in checked_products
    )

    # Override product_name with actual product text
    # This ensures order has correct product info
    product_name = product_text

    try:

        db.execute(
            """
            INSERT INTO orders
            (
                order_number,
                customer_name,
                product_name,
                price,
                status,
                expected_delivery,
                phone,
                address,
                city,
                pincode,
                payment_method,
                payment_status,
                upi_id,
                utr,
                card_holder_name,
                card_last4,
                emi_provider,
                emi_tenure,
                emi_reference,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_number,
                customer_name,
                product_name,
                price,
                "Confirmed",
                "3-7 business days",
                phone,
                address,
                city,
                pincode,
                payment_method,
                payment_status,
                upi_id,
                utr,
                card_holder_name,
                card_last4,
                emi_provider,
                emi_tenure,
                emi_reference,
                created_at
            )
        )

        # -------------------------------------------------
        # REDUCE STOCK
        # -------------------------------------------------

        for product, quantity in checked_products:

            db.execute(
                """
                UPDATE products

                SET stock = stock - ?

                WHERE id = ?
                  AND stock >= ?
                """,
                (
                    quantity,
                    product[0],
                    quantity
                )
            )

        db.commit()

    except sqlite3.IntegrityError:

        db.rollback()

        db.close()

        return {
            "success": False,
            "message":
                "Order already exists."
        }

    except Exception as error:

        db.rollback()

        print(
            "CHECKOUT ERROR:",
            repr(error)
        )

        db.close()

        return {
            "success": False,
            "message":
                "Unable to save order."
        }

    db.close()

    return {
        "success": True,

        "order_number":
            order_number,

        "payment_status":
            payment_status
    }


# =========================================================
# ORDER SUCCESS
# =========================================================

@app.get(
    "/order-success",
    response_class=HTMLResponse
)
def order_success(order: str = ""):

    safe_order = html.escape(
        order or "SKY-ORDER"
    )

    content = f"""

    <style>

    .success-box {{
        max-width: 650px;
        margin: 50px auto;
        padding: 45px 25px;
        text-align: center;
        border-radius: 25px;
        background: rgba(255,255,255,.045);
        border: 1px solid rgba(255,255,255,.08);
    }}

    .success-icon {{
        font-size: 65px;
        margin-bottom: 15px;
    }}

    .success-box h2 {{
        margin: 10px 0;
        font-size: 27px;
    }}

    .order-number {{
        display: inline-block;
        margin: 15px 0;
        padding: 10px 15px;
        border-radius: 10px;
        color: #a5b4fc;
        background: rgba(79,124,255,.10);
        font-weight: 700;
    }}

    .success-actions {{
        display: flex;
        justify-content: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 25px;
    }}

    </style>


    <div class="success-box">

        <div class="success-icon">
            🎉
        </div>

        <h2>
            Order Placed Successfully!
        </h2>

        <p style="color:#94a3b8;">
            Thank you for shopping with Skye Mart.
        </p>

        <div class="order-number">
            Order ID: {safe_order}
        </div>

        <p style="color:#71809a;font-size:12px;">
            Your demo order has been recorded locally.
        </p>


        <div class="success-actions">

            <a
                class="btn"
                href="/orders"
            >
                📦 View Orders
            </a>

            <a
                class="btn"
                href="/"
            >
                🛍️ Continue Shopping
            </a>

        </div>

    </div>

    """

    return page_shell(
        "Order Successful — Skye Mart",
        content
    )


# =========================================================
# PAGE SHELL WITH UPDATED CSS
# =========================================================

def page_shell(title, content):

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>{title} — AI Business Assistant</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    min-height: 100vh;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    color: #f8fafc;

    background:
        radial-gradient(
            circle at 20% 10%,
            rgba(79,124,255,.22),
            transparent 32%
        ),
        radial-gradient(
            circle at 80% 90%,
            rgba(118,76,255,.2),
            transparent 32%
        ),
        #070b16;

    padding: 30px;
}}

.container {{

    max-width: 1150px;

    margin: auto;
}}

.topbar {{

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-bottom: 30px;

    padding: 15px 16px;

    border-radius: 20px;

    background:
        rgba(255,255,255,.06);

    border:
        1px solid rgba(255,255,255,.1);

    backdrop-filter:
        blur(30px);
}}

.topbar h1 {{

    margin: 0;

    font-size: 17px;
}}

.back {{

    color: #aab5c8;

    text-decoration: none;

    padding: 9px 13px;

    border-radius: 12px;

    background:
        rgba(255,255,255,.05);
}}

.back:hover {{
    color: white;
}}

.grid {{

    display: grid;

    grid-template-columns:
        repeat(2, minmax(0, 1fr));

    gap: 12px;
}}

.card {{

    padding: 15px;

    border-radius: 20px;

    background:
        rgba(255,255,255,.06);

    border:
        1px solid rgba(255,255,255,.1);

    backdrop-filter:
        blur(25px);

    transition: .25s;
}}

.card:hover {{

    transform:
        translateY(-5px);

    background:
        rgba(255,255,255,.085);

    border-color:
        rgba(255,255,255,.18);
}}

.icon {{

    width: 52px;
    height: 52px;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 16px;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #704cff
        );

    font-size: 23px;

    margin-bottom: 18px;
}}

.card h2 {{

    margin: 0 0 8px;

    font-size: 15px;
}}

.card p {{

    color: #94a3b8;

    line-height: 1.6;

    font-size: 13px;
}}

.price {{

    font-size: 17px;

    font-weight: 700;

    margin:
        16px 0;
}}

.btn {{

    display: inline-block;

    padding: 10px 15px;

    border-radius: 12px;

    color: white;

    text-decoration: none;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #6748ec
        );

    font-size: 12px;

    width: 100%;
}}

.empty {{

    text-align: center;

    padding: 60px 20px;

    color: #64748b;
}}


/* =========================================================
   HORIZONTAL SCROLL
   ========================================================= */

.horizontal-scroll {{

    display: flex;

    gap: 12px;

    overflow-x: auto;

    overflow-y: hidden;

    padding: 6px 4px 16px;

    scroll-behavior: smooth;

    scrollbar-width: thin;

    -webkit-overflow-scrolling: touch;
}}

.horizontal-scroll::-webkit-scrollbar {{
    height: 4px;
}}

.horizontal-scroll::-webkit-scrollbar-thumb {{
    background: rgba(255,255,255,.2);

    border-radius: 20px;
}}

.horizontal-scroll .card {{
    flex: 0 0 auto;

    min-width: 200px;
}}


/* =========================================================
   MOBILE
   ========================================================= */

@media(max-width:650px) {{

    body {{
        padding: 15px;
    }}

    .topbar {{
        padding: 15px;
    }}
}}

@media(max-width:430px) {{

    .grid {{
        grid-template-columns: 1fr;
    }}
}}


/* =========================================================
   REDUCED MOTION
   ========================================================= */

@media(prefers-reduced-motion: reduce) {{

    html {{
        scroll-behavior: auto;
    }}

    *,
    *::before,
    *::after {{
        animation-duration: .01ms !important;
        transition-duration: .01ms !important;
    }}
}}

</style>

</head>

<body>

<div class="container">

    <div class="topbar">

        <h1>{title}</h1>

        <a class="back" href="/">
            ← Assistant
        </a>

    </div>

    {content}

</div>

</body>

</html>
"""


# =========================================================
# PREMIUM CUSTOMER PAGES WITH HORIZONTAL SCROLL
# =========================================================

@app.get("/products", response_class=HTMLResponse)
def products_page():

    products = get_products()

    if not products:

        content = """
        <div class="empty">
            No products are available right now.
        </div>
        """

    else:

        cards = ""

        for product in products:

            # Product fields: id, name, price, description, category, subcategory, image_url, stock
            category = product[4] or "General"
            subcategory = product[5] or ""
            stock = product[7] or 0
            stock_display = f"{stock} in stock" if stock > 0 else "Out of stock"
            image_url = html.escape(product[6] or "")

            product_icon = get_product_icon(
                product[1],
                product[4],
                product[5]
            )

            # Image or icon display
            if image_url:
                image_display = f'''
                <div
                    style="
                        width:100%;
                        height:180px;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        margin-bottom:15px;
                        border-radius:18px;
                        background:rgba(255,255,255,.04);
                        overflow:hidden;
                    "
                >
                    <img
                        src="{image_url}"
                        alt="{html.escape(product[1])}"
                        style="
                            width:100%;
                            height:100%;
                            object-fit:contain;
                        "
                        onerror="this.style.display='none';"
                    >
                </div>
                '''
            else:
                image_display = f'''
                <div class="icon">
                    {product_icon}
                </div>
                '''

            cards += f"""
            <div class="card">

                {image_display}

                <h2>{html.escape(product[1])}</h2>

                <div style="font-size:11px;color:#64748b;margin-bottom:8px;">
                    {html.escape(category)}
                    {f' → {html.escape(subcategory)}' if subcategory else ''}
                </div>

                <div class="price">
                    ₹{html.escape(str(product[2] or ""))}
                </div>

                <p>
                    {html.escape(product[3] or "")}
                </p>

                <div style="font-size:11px;color:#64748b;margin-top:8px;">
                    {stock_display}
                </div>

                <a
                    class="btn"
                    href="/products/{product[0]}"
                >
                    View Details →
                </a>

            </div>
            """

        content = f"""
        <div class="horizontal-scroll">
            {cards}
        </div>
        """

    return page_shell(
        "🛍️ Products",
        content
    )


@app.get("/orders", response_class=HTMLResponse)
def orders_page(order: str = ""):

    result_html = ""

    if order.strip():

        found = get_order(order.strip())

        if found:

            current_status = found[4]

            statuses = [
                "Pending",
                "Confirmed",
                "Processing",
                "Shipped",
                "Delivered",
                "Cancelled"
            ]

            if current_status == "Cancelled":
                status_index = 0
            else:
                status_index = (
                    statuses.index(current_status)
                    if current_status in statuses
                    else 0
                )

            # =====================================================
            # FORMAT ORDER PRICE
            # =====================================================

            price_value = found[3]

            if price_value is None:
                price_display = "Price unavailable"
            else:
                price_text = str(price_value).strip()

                # Remove currency symbols if already stored
                price_text = price_text.replace("₹", "")
                price_text = price_text.replace("INR", "")
                price_text = price_text.replace("inr", "")
                price_text = price_text.replace(",", "")
                price_text = price_text.strip()

                if price_text:
                    try:
                        price_display = f"₹{float(price_text):,.0f}"
                    except (ValueError, TypeError):
                        price_display = f"₹{price_text}"
                else:
                    price_display = "Price unavailable"

            timeline = ""

            for i, status in enumerate(statuses):

                if current_status == "Cancelled":

                    if status == "Pending":
                        state_class = "completed"
                        icon = "✓"

                    elif status == "Cancelled":
                        state_class = "cancelled"
                        icon = "×"

                    else:
                        state_class = "cancelled-disabled"
                        icon = "×"

                else:

                    if i < status_index:
                        state_class = "completed"
                        icon = "✓"

                    elif i == status_index:
                        state_class = "active"
                        icon = "●"

                    else:
                        state_class = "pending"
                        icon = "○"

                timeline += f"""
                <div class="timeline-item {state_class}">

                    <div class="timeline-icon">
                        {icon}
                    </div>

                    <div class="timeline-label">
                        {html.escape(status)}
                    </div>

                </div>
                """

            result_html = f"""
            <style>

            .order-card {{
                padding:28px;
                border-radius:25px;
                background:rgba(255,255,255,.06);
                border:1px solid rgba(255,255,255,.10);
                backdrop-filter:blur(30px);
                transition:.25s;
            }}

            .order-card:hover {{
                background:rgba(255,255,255,.085);
                border-color:rgba(255,255,255,.18);
            }}

            .order-header {{
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:15px;
                margin-bottom:25px;
                flex-wrap:wrap;
            }}

            .order-number {{
                font-size:22px;
                font-weight:700;
                letter-spacing:-.3px;
            }}

            .status-badge {{
                padding:8px 16px;
                border-radius:20px;
                background:rgba(79,124,255,.12);
                border:1px solid rgba(79,124,255,.18);
                color:#9bb5ff;
                font-size:12px;
                font-weight:600;
                text-transform:uppercase;
                letter-spacing:.5px;
            }}

            .order-info {{
                display:grid;
                grid-template-columns:
                    repeat(2,1fr);
                gap:12px;
                margin-bottom:30px;
            }}

            .info-box {{
                padding:16px 18px;
                border-radius:15px;
                background:rgba(255,255,255,.04);
                border:1px solid rgba(255,255,255,.07);
                transition:.2s;
            }}

            .info-box:hover {{
                background:rgba(255,255,255,.07);
                border-color:rgba(255,255,255,.12);
            }}

            .info-label {{
                color:#64748b;
                font-size:10px;
                text-transform:uppercase;
                letter-spacing:.5px;
                margin-bottom:6px;
            }}

            .info-value {{
                color:#e2e8f0;
                font-size:14px;
                font-weight:500;
            }}

            .info-value.price {{
                color:#93c5fd;
                font-size:18px;
                font-weight:700;
            }}

            .info-value.delivery {{
                color:#4ade80;
            }}

            .timeline {{
                margin-top:25px;
                position:relative;
            }}

            .timeline-item {{
                position:relative;
                display:flex;
                gap:15px;
                min-height:52px;
                animation:fadeIn .3s ease;
            }}

            @keyframes fadeIn {{
                from {{ opacity:0; transform:translateY(5px); }}
                to {{ opacity:1; transform:translateY(0); }}
            }}

            .timeline-item:not(:last-child)::after {{
                content:"";
                position:absolute;
                left:11px;
                top:30px;
                width:2px;
                height:30px;
                background:rgba(255,255,255,.10);
            }}

            .timeline-item.completed:not(:last-child)::after {{
                background:rgba(34,197,94,.20);
            }}

            .timeline-icon {{
                width:24px;
                height:24px;
                flex-shrink:0;
                display:flex;
                align-items:center;
                justify-content:center;
                border-radius:50%;
                background:rgba(255,255,255,.06);
                border:1px solid rgba(255,255,255,.10);
                font-size:11px;
                z-index:1;
                transition:.3s;
            }}

            .timeline-label {{
                padding-top:2px;
                font-size:13px;
                color:#64748b;
                transition:.3s;
            }}

            .timeline-item.completed .timeline-icon {{
                background:rgba(34,197,94,.12);
                border-color:rgba(34,197,94,.25);
                color:#4ade80;
            }}

            .timeline-item.completed .timeline-label {{
                color:#cbd5e1;
            }}

            .timeline-item.active .timeline-icon {{
                background:rgba(79,124,255,.18);
                border-color:rgba(79,124,255,.45);
                color:#93c5fd;
                box-shadow:0 0 18px rgba(79,124,255,.25);
                animation:pulse 2s infinite;
            }}

            @keyframes pulse {{
                0% {{ box-shadow: 0 0 18px rgba(79,124,255,.25); }}
                50% {{ box-shadow: 0 0 30px rgba(79,124,255,.4); }}
                100% {{ box-shadow: 0 0 18px rgba(79,124,255,.25); }}
            }}

            .timeline-item.active .timeline-label {{
                color:white;
                font-weight:600;
            }}

            .timeline-item.pending .timeline-label {{
                color:#475569;
            }}

            .timeline-item.pending .timeline-icon {{
                color:#475569;
            }}

            .timeline-item.cancelled {{
                color: #f87171;
            }}

            .timeline-item.cancelled .timeline-icon {{
                background: rgba(239,68,68,.15);
                border-color: #ef4444;
                color: #ef4444;
            }}

            .timeline-item.cancelled-disabled {{
                color: #64748b;
                opacity: .45;
            }}

            .timeline-item.cancelled-disabled .timeline-icon {{
                background: rgba(100,116,139,.08);
                border-color: #475569;
                color: #64748b;
            }}

            .progress-label {{
                display:flex;
                justify-content:space-between;
                align-items:center;
                margin-bottom:10px;
            }}

            .progress-label span {{
                font-size:12px;
                color:#64748b;
            }}

            @media(max-width:600px) {{

                .order-info {{
                    grid-template-columns:1fr;
                }}

                .order-header {{
                    align-items:flex-start;
                    flex-direction:column;
                }}

                .order-number {{
                    font-size:18px;
                }}

            }}

            </style>


            <div class="order-card">

                <div class="order-header">

                    <div class="order-number">
                        📦 Order #{html.escape(found[0])}
                    </div>

                    <div class="status-badge">
                        {html.escape(found[4])}
                    </div>

                </div>


                <div class="order-info">

                    <div class="info-box">

                        <div class="info-label">
                            👤 Customer
                        </div>

                        <div class="info-value">
                            {html.escape(found[1])}
                        </div>

                    </div>


                    <div class="info-box">

                        <div class="info-label">
                            🛍️ Product
                        </div>

                        <div class="info-value">
                            {html.escape(found[2])}
                        </div>

                    </div>


                    <div class="info-box">

                        <div class="info-label">
                            💰 Price
                        </div>

                        <div class="info-value price">
                            {price_display}
                        </div>

                    </div>


                    <div class="info-box">

                        <div class="info-label">
                            🚚 Expected Delivery
                        </div>

                        <div class="info-value delivery">
                            {html.escape(found[5] or "Not available")}
                        </div>

                    </div>

                </div>


                <div class="progress-label">

                    <h3 style="
                        margin:0;
                        font-size:14px;
                        font-weight:600;
                    ">
                        Order Progress
                    </h3>

                    <span>
                        {status_index + 1}/{len(statuses)}
                    </span>

                </div>


                <div class="timeline">

                    {timeline}

                </div>

            </div>
            """

        else:

            result_html = """
            <div class="card">

                <div class="icon">
                    ❌
                </div>

                <h2>
                    Order Not Found
                </h2>

                <p>
                    Please check your order number
                    and try again.
                </p>

            </div>
            """

    content = f"""

    <div class="card">

        <div class="icon">
            🚚
        </div>

        <h2>
            Track Your Order
        </h2>

        <p>
            Enter your order number below to track
            your order status and delivery progress.
        </p>

        <form method="get" style="margin-top:15px;">

            <input
                name="order"
                placeholder="Example: 1001"
                required
                style="
                    width:100%;
                    padding:14px;
                    border-radius:14px;
                    border:1px solid rgba(255,255,255,.1);
                    background:rgba(255,255,255,.05);
                    color:white;
                    outline:none;
                    font-size:14px;
                "
            >

            <br><br>

            <button
                class="btn"
                type="submit"
                style="border:0;cursor:pointer;font-size:13px;"
            >
                🔍 Track Order →
            </button>

        </form>

    </div>

    {result_html}

    """

    return page_shell(
        "📦 Order Tracking",
        content
    )


@app.get("/support", response_class=HTMLResponse)
def support_page():

    content = """
    <div class="horizontal-scroll">

        <div class="card">

            <div class="icon">
                🤖
            </div>

            <h2>AI Customer Support</h2>

            <p>
                Ask our AI assistant about products,
                prices, orders and business information.
            </p>

            <a class="btn" href="/support/chat">
                Open Assistant →
            </a>

        </div>


        <div class="card">

            <div class="icon">
                🛍️
            </div>

            <h2>Product Support</h2>

            <p>
                Need help choosing a product?
                Browse the complete product catalog.
            </p>

            <a class="btn" href="/products">
                Browse Products →
            </a>

        </div>


        <div class="card">

            <div class="icon">
                ❓
            </div>

            <h2>Frequently Asked Questions</h2>

            <p>
                Find answers to common customer
                questions.
            </p>

            <a class="btn" href="/faq">
                View FAQ →
            </a>

        </div>

    </div>
    """

    return page_shell(
        "💬 Customer Support",
        content
    )


# =========================================================
# UPDATED SUPPORT CHAT PAGE
# =========================================================

@app.get("/support/chat", response_class=HTMLResponse)
def support_chat():
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Customer Support</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #070b18;
            color: white;
        }

        .chat-box {
            max-width: 850px;
            margin: 40px auto;
            padding: 25px;
        }

        .header {
            padding: 22px;
            border-radius: 18px;
            background: #151d38;
            margin-bottom: 20px;
        }

        .messages {
            min-height: 450px;
            max-height: 65vh;
            overflow-y: auto;
            padding: 20px;
            border-radius: 18px;
            background: #111729;
            margin-bottom: 15px;
        }

        .message {
            padding: 14px 18px;
            border-radius: 14px;
            margin: 10px 0;
            max-width: 75%;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .ai {
            background: #20283d;
        }

        .user {
            background: #4f5cff;
            margin-left: auto;
        }

        .input-row {
            display: flex;
            gap: 10px;
        }

        input {
            flex: 1;
            padding: 16px;
            border-radius: 12px;
            border: 1px solid #334155;
            background: #111729;
            color: white;
            outline: none;
        }

        button {
            padding: 16px 22px;
            border: 0;
            border-radius: 12px;
            background: #5965ff;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }

        .actions {
            display: flex;
            gap: 10px;
        }

        .back-btn {
            padding: 10px 15px;
            border-radius: 12px;
            background: #20283d;
            color: white;
            text-decoration: none;
        }

        .exit-btn {
            padding: 10px 15px;
            border: 0;
            border-radius: 12px;
            background: #ef4444;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }

        @media(max-width: 700px) {
            .chat-box {
                margin: 0 auto;
                padding: 15px;
            }

            .message {
                max-width: 90%;
            }

            .header {
                padding: 18px;
            }

            .actions {
                width: 100%;
            }
        }
    </style>
</head>

<body>

<div class="chat-box">

    <div class="header">

        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:15px;
            flex-wrap:wrap;
        ">

            <div>
                <h1>AI Customer Support</h1>
                <p>Ask about products, orders, prices or general questions.</p>
            </div>

            <div class="actions">

                <a href="/support" class="back-btn">
                    ← Support
                </a>

                <button
                    type="button"
                    class="exit-btn"
                    onclick="exitChat()"
                >
                    Exit Chat
                </button>

            </div>

        </div>

    </div>


    <div class="messages" id="messages">

        <div class="message ai">
            Hello! I'm your AI customer support assistant.
            How can I help you today?
        </div>

    </div>


    <div class="input-row">

        <input
            id="messageInput"
            type="text"
            placeholder="Type your question..."
            autocomplete="off"
        >

        <button
            type="button"
            onclick="sendMessage()"
        >
            Send
        </button>

    </div>

</div>


<script>

const input = document.getElementById("messageInput");
const messages = document.getElementById("messages");

const CHAT_KEY = "ai_business_chat";


function saveChat() {

    localStorage.setItem(
        CHAT_KEY,
        messages.innerHTML
    );

}


function loadChat() {

    const savedChat =
        localStorage.getItem(CHAT_KEY);

    if (savedChat) {

        messages.innerHTML = savedChat;

        messages.scrollTop =
            messages.scrollHeight;

    }

}


function addMessage(text, type) {

    const message =
        document.createElement("div");

    message.className =
        "message " + type;

    message.textContent = text;

    messages.appendChild(message);

    messages.scrollTop =
        messages.scrollHeight;

    saveChat();

}


function exitChat() {

    const confirmed = confirm(
        "Exit chat? Your current chat history will be cleared."
    );

    if (!confirmed) {
        return;
    }

    localStorage.removeItem(CHAT_KEY);

    window.location.href = "/support";

}


async function sendMessage() {

    const message =
        input.value.trim();

    if (!message) {
        return;
    }

    addMessage(message, "user");

    input.value = "";

    const loading =
        document.createElement("div");

    loading.className =
        "message ai";

    loading.textContent =
        "Thinking...";

    messages.appendChild(loading);

    messages.scrollTop =
        messages.scrollHeight;


    try {

        const response =
            await fetch("/chat", {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    message: message
                })

            });


        const data =
            await response.json();

        loading.remove();

        addMessage(
            data.reply ||
            "Sorry, I couldn't respond right now.",
            "ai"
        );


    } catch (error) {

        loading.remove();

        addMessage(
            "Sorry, something went wrong. Please try again.",
            "ai"
        );

    }

}


input.addEventListener(
    "keydown",
    function(event) {

        if (event.key === "Enter") {

            event.preventDefault();

            sendMessage();

        }

    }
);


loadChat();

</script>

</body>
</html>
""")


@app.get("/faq", response_class=HTMLResponse)
def faq_page():

    faqs = get_faqs()

    if not faqs:

        content = """
        <div class="empty">
            No FAQs have been added yet.
        </div>
        """

    else:

        cards = ""

        for faq in faqs:

            cards += f"""
            <div class="card">

                <h2>
                    FAQ: {html.escape(faq[1] or "")}
                </h2>

                <p>
                    {html.escape(faq[2] or "")}
                </p>

            </div>
            """

        content = f"""
        <div class="grid">
            {cards}
        </div>
        """

    return page_shell(
        "Frequently Asked Questions",
        content
    )


@app.get("/about", response_class=HTMLResponse)
def about_page():

    business = get_business()

    content = f"""
    <div class="card">

        <div class="icon">
            Business
        </div>

        <h2>
            {html.escape(business[0] or "")}
        </h2>

        <p>
            {html.escape(business[1] or "")}
        </p>

    </div>
    """

    return page_shell(
        "About Our Business",
        content
    )


# =========================================================
# PREMIUM ADMIN DASHBOARD
# =========================================================

@app.get("/admin", response_class=HTMLResponse)
def admin():

    business = get_business()
    products = get_products()
    faqs = get_faqs()
    orders = get_orders()
    categories = get_categories()

    business_name = html.escape(business[0] or "")
    business_description = html.escape(business[1] or "")

    product_count = len(products)
    faq_count = len(faqs)
    order_count = len(orders)

    pending_orders = sum(
        1 for order in orders
        if order[5] == "Pending"
    )

    processing_orders = sum(
        1 for order in orders
        if order[5] == "Processing"
    )

    shipped_orders = sum(
        1 for order in orders
        if order[5] == "Shipped"
    )

    delivered_orders = sum(
        1 for order in orders
        if order[5] == "Delivered"
    )

    cancelled_orders = sum(
        1 for order in orders
        if order[5] == "Cancelled"
    )

    # Generate category options for dropdown
    category_options = ""

    for category in categories:
        category_options += f"""
        <option value="{html.escape(category[1])}">
            {html.escape(category[1])}
        </option>
        """

    # -----------------------------------------------------
    # PRODUCTS
    # -----------------------------------------------------

    products_html = ""

    for product in products:

        product_id = product[0]
        name = html.escape(product[1] or "")
        price = html.escape(str(product[2] or ""))
        description = html.escape(product[3] or "")
        category = html.escape(product[4] or "General")
        subcategory = html.escape(product[5] or "")
        image_url = html.escape(product[6] or "")
        stock = product[7] or 0

        products_html += f"""
        <div class="product-card">

            <div class="icon">
                Business
            </div>

            <div class="product-info">

                <div class="product-title">
                    {name}
                </div>

                <div class="product-price">
                    ₹{price}
                </div>

                <div class="product-description">
                    📂 {category}
                    {f' → {subcategory}' if subcategory else ''}
                    &nbsp; • &nbsp;
                    {
                        "🟢 In Stock"
                        if stock > 0
                        else
                        "🔴 Out of Stock"
                    }
                    &nbsp; • &nbsp;
                    📦 Quantity:
                    {stock}
                    {f'<br>🖼️ {image_url}' if image_url else ''}
                    <br>{description}
                </div>

            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap;">

                <a
                    href="/admin/product/edit/{product_id}"
                    style="
                        color:#93c5fd;
                        text-decoration:none;
                        font-size:12px;
                        padding:8px 12px;
                        border-radius:10px;
                        background:rgba(79,124,255,.10);
                        border:1px solid rgba(79,124,255,.15);
                    "
                >
                    Edit
                </a>

                <a
                    class="delete-btn"
                    href="/admin/product/delete/{product_id}"
                    onclick="return confirm('Delete this product?')"
                >
                    Delete
                </a>

            </div>

        </div>
        """

    if not products_html:
        products_html = """
        <div class="empty">
            📦 No products added yet.
        </div>
        """

    # -----------------------------------------------------
    # FAQS
    # -----------------------------------------------------

    faqs_html = ""

    for faq in faqs:

        faq_id = faq[0]

        question = html.escape(faq[1] or "")
        answer = html.escape(faq[2] or "")

        faqs_html += f"""
        <div class="faq-card">

            <div class="faq-icon">
                ❓
            </div>

            <div class="faq-content">

                <div class="faq-question">
                    {question}
                </div>

                <div class="faq-answer">
                    {answer}
                </div>

            </div>

            <a
                class="delete-btn"
                href="/admin/faq/delete/{faq_id}"
                onclick="return confirm('Delete this FAQ?')"
            >
                Delete
            </a>

        </div>
        """

    if not faqs_html:
        faqs_html = """
        <div class="empty">
            ❓ No FAQs added yet.
        </div>
        """

    # -----------------------------------------------------
    # ORDERS
    # -----------------------------------------------------

    orders_html = ""

    for order in orders:

        order_id = order[0]
        order_number = html.escape(order[1] or "")
        customer_name = html.escape(order[2] or "")
        product_name = html.escape(order[3] or "")
        price = html.escape(str(order[4] or ""))
        status = html.escape(order[5] or "")
        delivery = html.escape(order[6] or "")
        phone = html.escape(order[7] or "")
        address = html.escape(order[8] or "")
        city = html.escape(order[9] or "")
        pincode = html.escape(order[10] or "")
        payment_method = html.escape(order[11] or "")
        payment_status = html.escape(order[12] or "")
        upi_id = html.escape(order[13] or "")
        utr = html.escape(order[14] or "")
        card_holder_name = html.escape(order[15] or "")
        card_last4 = html.escape(order[16] or "")
        emi_provider = html.escape(order[17] or "")
        emi_tenure = html.escape(order[18] or "")
        emi_reference = html.escape(order[19] or "")
        created_at = html.escape(order[20] or "")

        # Status badge class
        status_class = f"status-{status.lower()}"

        orders_html += f"""
        <div class="product-card">

            <div class="product-icon">
                📦
            </div>

            <div class="product-info">

                <div class="product-title">
                    Order #{order_number}
                </div>

                <div class="product-price">
                    {product_name} — ₹{price}
                </div>

                <div style="margin-top:8px;font-size:12px;line-height:1.8;color:#cbd5e1;">

                    <div>
                        👤 Customer:
                        <strong>{customer_name}</strong>
                    </div>

                    <div>
                        📞 Phone:
                        <strong>{phone or "Not available"}</strong>
                    </div>

                    <div>
                        📍 Address:
                        <strong>{address or "Not available"}</strong>
                    </div>

                    <div>
                        🏙️ City:
                        <strong>{city or "Not available"}</strong>
                    </div>

                    <div>
                        📮 Pincode:
                        <strong>{pincode or "Not available"}</strong>
                    </div>

                    <div>
                        💳 Payment:
                        <strong>{payment_method or "Not available"}</strong>
                    </div>

                    <div>
                        💰 Payment Status:
                        <strong>{payment_status or "Pending"}</strong>
                    </div>

                    <div>
                        🆔 UPI ID:
                        <strong>{upi_id or "Not provided"}</strong>
                    </div>

                    <div>
                        🔑 UTR:
                        <strong>{utr or "Not provided"}</strong>
                    </div>

                    <div>
                        💳 Card Holder:
                        <strong>{card_holder_name or "Not provided"}</strong>
                    </div>

                    <div>
                        🔢 Last 4:
                        <strong>{card_last4 or "Not provided"}</strong>
                    </div>

                    <div>
                        🏦 EMI Provider:
                        <strong>{emi_provider or "Not provided"}</strong>
                    </div>

                    <div>
                        📅 EMI Tenure:
                        <strong>{emi_tenure or "Not provided"}</strong>
                    </div>

                    <div>
                        📝 EMI Reference:
                        <strong>{emi_reference or "Not provided"}</strong>
                    </div>

                    <div>
                        📌 Order Status:
                        <span class="{status_class}">
                            {status}
                        </span>
                    </div>

                    <div>
                        🚚 Delivery:
                        <strong>{delivery or "Not set"}</strong>
                    </div>

                    <div>
                        🕐 Created:
                        <strong>{created_at or "Not available"}</strong>
                    </div>

                </div>

            </div>

            <div
                style="
                    display:flex;
                    gap:7px;
                    flex-wrap:wrap;
                    align-items:center;
                "
            >

                <a
                    href="/admin/order/edit/{order_id}"
                    style="
                        color:#93c5fd;
                        text-decoration:none;
                        padding:9px 12px;
                        border-radius:10px;
                        background:rgba(79,124,255,.10);
                    "
                >
                    ✏️ Edit
                </a>

                <a
                    class="delete-btn"
                    href="/admin/order/delete/{order_id}"
                    onclick="
                        return confirm(
                            'Delete this order permanently?'
                        )
                    "
                >
                    🗑️ Delete
                </a>

            </div>

        </div>
        """

    if not orders_html:
        orders_html = """
        <div class="empty">
            📦 No orders created yet.
        </div>
        """

    # -----------------------------------------------------
    # PAGE
    # -----------------------------------------------------

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Business Admin</title>


<style>

* {{
    box-sizing: border-box;
}}


:root {{

    --bg: #050816;

    --panel:
        rgba(255,255,255,.055);

    --panel-hover:
        rgba(255,255,255,.085);

    --border:
        rgba(255,255,255,.10);

    --text:
        #f8fafc;

    --muted:
        #8b98ad;

    --blue:
        #4f7cff;

    --purple:
        #764cff;

}}


html {{
    scroll-behavior: smooth;
}}


body {{

    margin: 0;

    min-height: 100vh;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    color: var(--text);

    background:

        radial-gradient(
            circle at 10% 10%,
            rgba(79,124,255,.20),
            transparent 28%
        ),

        radial-gradient(
            circle at 90% 85%,
            rgba(118,76,255,.18),
            transparent 30%
        ),

        var(--bg);

}}


body::before {{

    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    background:
        linear-gradient(
            120deg,
            rgba(255,255,255,.025),
            transparent 40%
        );

}}


/* =====================================================
   STATS GRID
===================================================== */

.stats-grid {{
    display:grid;
    grid-template-columns:
        repeat(auto-fit,minmax(150px,1fr));
    gap:12px;
    margin-bottom:25px;
}}


.stat-card {{
    padding:20px;
    border-radius:18px;

    background:
        rgba(255,255,255,.055);

    border:
        1px solid
        rgba(255,255,255,.10);
}}


.stat-number {{
    font-size:28px;
    font-weight:800;
}}


.stat-label {{
    margin-top:5px;
    color:#8b98ad;
    font-size:12px;
}}


/* =====================================================
   STATUS BADGES
===================================================== */

.status-pending,
.status-confirmed,
.status-processing,
.status-shipped,
.status-delivered,
.status-cancelled {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
}}


.status-pending {{
    background: rgba(234,179,8,.15);
    color: #facc15;
}}


.status-confirmed {{
    background: rgba(59,130,246,.15);
    color: #60a5fa;
}}


.status-processing {{
    background: rgba(168,85,247,.15);
    color: #c084fc;
}}


.status-shipped {{
    background: rgba(14,165,233,.15);
    color: #38bdf8;
}}


.status-delivered {{
    background: rgba(34,197,94,.15);
    color: #4ade80;
}}


.status-cancelled {{
    background: rgba(239,68,68,.15);
    color: #f87171;
}}


/* =====================================================
   LAYOUT
===================================================== */

.app {{

    min-height: 100vh;

    display: flex;

}}


/* =====================================================
   SIDEBAR
===================================================== */

.sidebar {{

    position: fixed;

    left: 0;
    top: 0;
    bottom: 0;

    width: 250px;

    padding: 24px;

    background:
        rgba(7,12,28,.72);

    border-right:
        1px solid var(--border);

    backdrop-filter:
        blur(35px);

    -webkit-backdrop-filter:
        blur(35px);

}}


.brand {{

    display: flex;

    align-items: center;

    gap: 12px;

    margin-bottom: 35px;

}}


.brand-icon {{

    width: 45px;
    height: 45px;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 15px;

    background:
        linear-gradient(
            135deg,
            var(--blue),
            var(--purple)
        );

    box-shadow:
        0 10px 35px
        rgba(79,124,255,.30);

    font-size: 21px;

}}


.brand-title {{

    font-size: 15px;

    font-weight: 700;

}}


.brand-subtitle {{

    color: #65738a;

    font-size: 10px;

    margin-top: 3px;

}}


.nav-label {{

    color: #5f6d83;

    font-size: 10px;

    letter-spacing: 1.5px;

    text-transform: uppercase;

    margin:
        25px 0 10px;

}}


.nav a {{

    display: flex;

    align-items: center;

    gap: 10px;

    padding: 12px;

    margin-bottom: 5px;

    border-radius: 13px;

    color: #9ba8bc;

    text-decoration: none;

    font-size: 12px;

    transition: .2s;

}}


.nav a:hover,
.nav a.active {{

    color: white;

    background:
        rgba(255,255,255,.07);

}}


.sidebar-bottom {{

    position: absolute;

    left: 24px;
    right: 24px;
    bottom: 24px;

}}


.online {{

    display: flex;

    align-items: center;

    gap: 8px;

    padding: 11px;

    border-radius: 13px;

    background:
        rgba(34,197,94,.06);

    border:
        1px solid
        rgba(34,197,94,.10);

    color: #8d9aab;

    font-size: 11px;

}}


.dot {{

    width: 7px;
    height: 7px;

    border-radius: 50%;

    background: #22c55e;

    box-shadow:
        0 0 12px #22c55e;

}}


/* =====================================================
   MAIN
===================================================== */

.main {{

    margin-left: 250px;

    width: calc(100% - 250px);

    padding: 28px;

}}


.topbar {{

    display: flex;

    align-items: center;

    justify-content: space-between;

    margin-bottom: 28px;

}}


.topbar h1 {{

    margin: 0;

    font-size: 24px;

}}


.topbar p {{

    margin: 6px 0 0;

    color: var(--muted);

    font-size: 12px;

}}


.assistant-btn {{

    color: white;

    text-decoration: none;

    padding: 11px 15px;

    border-radius: 13px;

    background:
        rgba(255,255,255,.06);

    border:
        1px solid var(--border);

    backdrop-filter:
        blur(20px);

    font-size: 12px;

    transition: .2s;

}}


.assistant-btn:hover {{

    background:
        rgba(255,255,255,.10);

}}


/* =====================================================
   STATS
===================================================== */

.stats {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 15px;

    margin-bottom: 22px;

}}


.stat {{

    padding: 20px;

    border-radius: 21px;

    background:
        var(--panel);

    border:
        1px solid var(--border);

    backdrop-filter:
        blur(25px);

    transition: .2s;

}}


.stat:hover {{

    transform:
        translateY(-2px);

    background:
        var(--panel-hover);

}}


.stat-icon {{

    width: 40px;
    height: 40px;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background:
        rgba(79,124,255,.12);

    margin-bottom: 13px;

}}


.stat-number {{

    font-size: 25px;

    font-weight: 700;

}}


.stat-label {{

    color: var(--muted);

    font-size: 11px;

    margin-top: 3px;

}}


/* =====================================================
   CARDS
===================================================== */

.card {{

    padding: 24px;

    margin-bottom: 20px;

    border-radius: 23px;

    background:
        var(--panel);

    border:
        1px solid var(--border);

    backdrop-filter:
        blur(30px);

    -webkit-backdrop-filter:
        blur(30px);

}}


.card-header {{

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-bottom: 20px;

}}


.card-title {{

    margin: 0;

    font-size: 16px;

}}


.card-subtitle {{

    color: var(--muted);

    font-size: 11px;

    margin-top: 4px;

}}


/* =====================================================
   FORMS
===================================================== */

label {{

    display: block;

    color: #aeb9c9;

    font-size: 11px;

    margin-bottom: 7px;

}}


input,
textarea,
select {{

    width: 100%;

    padding: 13px 14px;

    margin-bottom: 15px;

    border-radius: 13px;

    border:
        1px solid
        rgba(255,255,255,.09);

    outline: none;

    background:
        rgba(255,255,255,.045);

    color: white;

    font-family: inherit;

    font-size: 13px;

    transition: .2s;

}}


input:focus,
textarea:focus,
select:focus {{

    border-color:
        rgba(79,124,255,.55);

    background:
        rgba(255,255,255,.065);

    box-shadow:
        0 0 0 3px
        rgba(79,124,255,.08);

}}


select option {{
    background: #1a1f2e;
    color: white;
}}


textarea {{

    resize: vertical;

    min-height: 90px;

}}


.primary-btn {{

    border: 0;

    padding: 12px 18px;

    border-radius: 13px;

    color: white;

    cursor: pointer;

    background:
        linear-gradient(
            135deg,
            var(--blue),
            var(--purple)
        );

    font-size: 12px;

    font-weight: 600;

    box-shadow:
        0 8px 25px
        rgba(79,124,255,.18);

}}


.primary-btn:hover {{

    filter: brightness(1.1);

}}


/* =====================================================
   PRODUCT / ORDER
===================================================== */

.product-card {{

    display: flex;

    align-items: center;

    gap: 15px;

    padding: 16px;

    margin-top: 10px;

    border-radius: 17px;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.07);

}}


.product-icon {{

    width: 45px;
    height: 45px;

    flex-shrink: 0;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 13px;

    background:
        rgba(79,124,255,.10);

    font-size: 19px;

}}


.product-info {{

    flex: 1;

    min-width: 0;

}}


.product-title {{

    font-size: 13px;

    font-weight: 600;

}}


.product-price {{

    color: #9bb5ff;

    font-size: 12px;

    margin-top: 3px;

}}


.product-description {{

    color: var(--muted);

    font-size: 10px;

    margin-top: 5px;

    line-height: 1.5;

}}


.delete-btn {{

    color: #fb7185;

    text-decoration: none;

    font-size: 10px;

    padding: 8px 10px;

    border-radius: 10px;

    background:
        rgba(244,63,94,.06);

    border:
        1px solid
        rgba(244,63,94,.10);

}}


.delete-btn:hover {{

    background:
        rgba(244,63,94,.12);

}}


/* =====================================================
   FAQ
===================================================== */

.faq-card {{

    display: flex;

    align-items: flex-start;

    gap: 13px;

    padding: 16px;

    margin-top: 10px;

    border-radius: 17px;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.07);

}}


.faq-icon {{

    width: 40px;
    height: 40px;

    flex-shrink: 0;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background:
        rgba(118,76,255,.10);

}}


.faq-content {{

    flex: 1;

}}


.faq-question {{

    font-size: 13px;

    font-weight: 600;

}}


.faq-answer {{

    color: var(--muted);

    font-size: 11px;

    line-height: 1.5;

    margin-top: 6px;

}}


.empty {{

    padding: 25px;

    text-align: center;

    color: #64748b;

    font-size: 12px;

    border-radius: 15px;

    background:
        rgba(255,255,255,.025);

}}


/* =====================================================
   MOBILE
===================================================== */

@media(max-width: 800px) {{

    .sidebar {{

        position: static;

        width: 100%;

        height: auto;

        border-right: 0;

        border-bottom:
            1px solid var(--border);

    }}

    .sidebar-bottom {{

        position: static;

        margin-top: 25px;

    }}

    .app {{

        display: block;

    }}

    .main {{

        margin-left: 0;

        width: 100%;

        padding: 18px;

    }}

    .stats {{

        grid-template-columns: 1fr 1fr;

    }}

    .topbar {{

        align-items: flex-start;

        gap: 15px;

    }}

}}


@media(max-width: 500px) {{

    .stats {{

        grid-template-columns: 1fr;

    }}

    .product-card,
    .faq-card {{

        align-items: flex-start;

    }}

    .delete-btn {{

        font-size: 9px;

    }}

}}

</style>

</head>


<body>


<div class="app">


    <!-- SIDEBAR -->

    <aside class="sidebar">


        <div class="brand">

            <div class="brand-icon">
                ✦
            </div>

            <div>

                <div class="brand-title">
                    AI Business
                </div>

                <div class="brand-subtitle">
                    ADMIN CONSOLE
                </div>

            </div>

        </div>


        <div class="nav-label">
            Management
        </div>


        <nav class="nav">

            <a
                href="/admin"
                class="active"
            >
                📊 Dashboard
            </a>

            <a href="#business">
                🏪 Business
            </a>

            <a href="#categories">
                📂 Categories
            </a>

            <a href="#products">
                📦 Products
            </a>

            <a href="#orders">
                📦 Orders
            </a>

            <a href="#faqs">
                ❓ FAQs
            </a>

        </nav>


        <div class="sidebar-bottom">

            <div class="online">

                <span class="dot"></span>

                System Online

            </div>

        </div>


    </aside>


    <!-- MAIN -->

    <main class="main">


        <div class="topbar">

            <div>

                <h1>
                    Admin Dashboard
                </h1>

                <p>
                    Manage your business assistant
                    from one place.
                </p>

            </div>


            <a
                class="assistant-btn"
                href="/"
            >
                ✦ Open Assistant
            </a>

        </div>


        <!-- STATS -->

        <div class="stats-grid">

            <div class="stat-card">
                <div class="stat-number">
                    {order_count}
                </div>
                <div class="stat-label">
                    Total Orders
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-number">
                    {pending_orders}
                </div>
                <div class="stat-label">
                    Pending
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-number">
                    {processing_orders}
                </div>
                <div class="stat-label">
                    Processing
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-number">
                    {shipped_orders}
                </div>
                <div class="stat-label">
                    Shipped
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-number">
                    {delivered_orders}
                </div>
                <div class="stat-label">
                    Delivered
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-number">
                    {cancelled_orders}
                </div>
                <div class="stat-label">
                    Cancelled
                </div>
            </div>

        </div>


        <!-- BUSINESS -->

        <section
            class="card"
            id="business"
        >

            <div class="card-header">

                <div>

                    <h2 class="card-title">
                        🏪 Business Information
                    </h2>

                    <div class="card-subtitle">
                        Update the information used
                        by your AI assistant.
                    </div>

                </div>

            </div>


            <form
                method="post"
                action="/admin/business"
            >


                <label>
                    Business Name
                </label>

                <input
                    name="name"
                    value="{business_name}"
                    required
                >


                <label>
                    Business Description
                </label>

                <textarea
                    name="description"
                    required
                >{business_description}</textarea>


                <button
                    class="primary-btn"
                    type="submit"
                >
                    Save Business
                </button>


            </form>

        </section>


        <!-- CATEGORIES -->

        <section
            class="card"
            id="categories"
        >

            <div class="card-header">

                <div>
                    <h2 class="card-title">
                        📂 Categories
                    </h2>

                    <div class="card-subtitle">
                        Create and manage product categories.
                    </div>
                </div>

            </div>

            <form
                method="post"
                action="/admin/category"
            >

                <label>
                    Category Name
                </label>

                <input
                    name="name"
                    placeholder="Example: Smartphones"
                    required
                >

                <button
                    class="primary-btn"
                    type="submit"
                >
                    + Add Category
                </button>

            </form>

        </section>


        <!-- PRODUCTS -->

        <section
            class="card"
            id="products"
        >

            <div class="card-header">

                <div>

                    <h2 class="card-title">
                        📦 Products
                    </h2>

                    <div class="card-subtitle">
                        Add and manage your products.
                    </div>

                </div>

            </div>


            <form
                method="post"
                action="/admin/product"
            >

                <label>
                    Product Name
                </label>

                <input
                    name="name"
                    placeholder="Example: iPhone 17 Pro Max"
                    required
                >

                <label>
                    Category
                </label>

                <input
                    name="category"
                    placeholder="General"
                    required
                >

                <label>
                    Subcategory
                </label>

                <input
                    name="subcategory"
                    placeholder="Example: Smartphones"
                >

                <label>
                    Price
                </label>

                <input
                    name="price"
                    placeholder="65000"
                    required
                >

                <label>
                    Description
                </label>

                <textarea
                    name="description"
                    placeholder="Product description"
                ></textarea>

                <label>
                    Product Image URL
                </label>

                <input
                    type="url"
                    name="image_url"
                    placeholder="https://example.com/product-image.jpg"
                >

                <label>
                    Stock Quantity
                </label>

                <input
                    type="number"
                    name="stock"
                    min="0"
                    value="0"
                    placeholder="Example: 10"
                >

                <button
                    class="primary-btn"
                    type="submit"
                >
                    + Add Product
                </button>

            </form>


            <div style="margin-top:25px">

                {products_html}

            </div>


        </section>


        <!-- ORDERS -->

        <section
            class="card"
            id="orders"
        >

            <div class="card-header">

                <div>

                    <h2 class="card-title">
                        📦 Orders
                    </h2>

                    <div class="card-subtitle">
                        Create and manage customer orders.
                    </div>

                </div>

            </div>


            <form
                method="post"
                action="/admin/order"
            >

                <label>
                    Order Number
                </label>

                <input
                    name="order_number"
                    placeholder="Example: 1002"
                    required
                >


                <label>
                    Customer Name
                </label>

                <input
                    name="customer_name"
                    placeholder="Customer name"
                    required
                >


                <label>
                    Product Name
                </label>

                <input
                    name="product_name"
                    placeholder="Example: Gaming Laptop"
                    required
                >


                <label>
                    Price
                </label>

                <input
                    name="price"
                    placeholder="Auto-fetch from product if left blank"
                    style="color:#94a3b8;"
                >


                <label>
                    Status
                </label>

                <select
                    name="status"
                >

                    <option>Pending</option>
                    <option>Confirmed</option>
                    <option>Processing</option>
                    <option>Shipped</option>
                    <option>Delivered</option>
                    <option>Cancelled</option>

                </select>


                <label>
                    Expected Delivery
                </label>

                <input
                    name="expected_delivery"
                    placeholder="18 August 2026"
                >


                <button
                    class="primary-btn"
                    type="submit"
                >
                    + Create Order
                </button>

            </form>


            <div style="margin-top:25px">

                {orders_html}

            </div>

        </section>


        <!-- FAQ -->

        <section
            class="card"
            id="faqs"
        >

            <div class="card-header">

                <div>

                    <h2 class="card-title">
                        ❓ FAQs
                    </h2>

                    <div class="card-subtitle">
                        Add frequently asked questions
                        for your AI assistant.
                    </div>

                </div>

            </div>


            <form
                method="post"
                action="/admin/faq"
            >


                <label>
                    Question
                </label>

                <input
                    name="question"
                    placeholder="Example: What is your return policy?"
                    required
                >


                <label>
                    Answer
                </label>

                <textarea
                    name="answer"
                    placeholder="Write the answer..."
                    required
                ></textarea>


                <button
                    class="primary-btn"
                    type="submit"
                >
                    + Add FAQ
                </button>


            </form>


            <div style="margin-top:25px">

                {faqs_html}

            </div>


        </section>


    </main>


</div>


</body>

</html>
"""


# =========================================================
# ADMIN ACTIONS
# =========================================================

@app.post("/admin/business")
def save_business(
    name: str = Form(...),
    description: str = Form(...)
):

    db = get_db()

    db.execute(
        """
        UPDATE business
        SET name = ?, description = ?
        WHERE id = 1
        """,
        (
            name.strip(),
            description.strip()
        )
    )

    db.commit()
    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.post("/admin/category")
def add_category(
    name: str = Form(...)
):

    name = name.strip()

    if not name:
        return RedirectResponse(
            "/admin",
            status_code=303
        )

    db = get_db()

    db.execute(
        """
        INSERT OR IGNORE INTO categories (name)
        VALUES (?)
        """,
        (name,)
    )

    db.commit()
    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# =========================================================
# PRODUCT ADD
# =========================================================

@app.post("/admin/product")
def add_product(
    name: str = Form(...),
    price: str = Form(""),
    category: str = Form("General"),
    subcategory: str = Form(""),
    description: str = Form(""),
    image_url: str = Form(""),
    stock: str = Form("0")
):

    db = get_db()

    try:

        name = name.strip()
        price = clean_price(price)
        category = category.strip() or "General"
        subcategory = subcategory.strip()
        description = description.strip()
        image_url = image_url.strip()

        try:
            stock_value = max(0, int(stock or 0))
        except (ValueError, TypeError):
            stock_value = 0

        db.execute(
            """
            INSERT INTO products
            (
                name,
                price,
                description,
                category,
                subcategory,
                image_url,
                stock
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                price,
                description,
                category,
                subcategory,
                image_url,
                stock_value
            )
        )

        db.commit()

    finally:
        db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# =========================================================
# PRODUCT EDIT
# =========================================================

@app.get(
    "/admin/product/edit/{product_id}",
    response_class=HTMLResponse
)
def edit_product_page(product_id: int):

    db = get_db()

    product = db.execute(
        """
        SELECT
            id,
            name,
            price,
            description,
            category,
            subcategory,
            image_url,
            stock
        FROM products
        WHERE id = ?
        """,
        (product_id,)
    ).fetchone()

    db.close()

    if not product:
        return HTMLResponse(
            "Product not found",
            status_code=404
        )

    image_url = str(product[6] or "")

    return HTMLResponse(
        f"""
<!DOCTYPE html>
<html>
<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Edit Product</title>

    <style>

        body {{
            margin:0;
            min-height:100vh;
            background:#050816;
            color:white;
            font-family:Arial,sans-serif;
        }}

        .box {{
            max-width:650px;
            margin:60px auto;
            padding:30px;
            background:#111827;
            border-radius:20px;
        }}

        label {{
            display:block;
            margin-top:18px;
            margin-bottom:7px;
        }}

        input,
        textarea,
        select {{
            width:100%;
            padding:13px;
            box-sizing:border-box;
            border-radius:10px;
            border:1px solid #334155;
            background:#0b1220;
            color:white;
        }}

        textarea {{
            min-height:120px;
        }}

        button {{
            margin-top:25px;
            padding:13px 20px;
            border:0;
            border-radius:10px;
            background:#4f7cff;
            color:white;
            cursor:pointer;
            font-weight:bold;
        }}

        .back {{
            color:#94a3b8;
            text-decoration:none;
        }}

    </style>

</head>

<body>

<div class="box">

    <a
        class="back"
        href="/admin"
    >
        ← Back to Dashboard
    </a>

    <h1>Edit Product</h1>

    <form
        method="post"
        action="/admin/product/edit/{product_id}"
    >

        <label>Product Name</label>

        <input
            name="name"
            value="{html.escape(product[1] or '')}"
            required
        >

        <label>Price</label>

        <input
            name="price"
            value="{html.escape(str(product[2] or ''))}"
            required
        >

        <label>Category</label>

        <input            name="category"
            value="{html.escape(product[4] or 'General')}"
            required
        >

        <label>Subcategory</label>

        <input
            name="subcategory"
            value="{html.escape(product[5] or '')}"
        >

        <label>Description</label>

        <textarea
            name="description"
        >{html.escape(product[3] or '')}</textarea>

        <label>Product Image URL</label>

        <input
            type="url"
            name="image_url"
            value="{html.escape(str(image_url or ''), quote=True)}"
            placeholder="https://example.com/product-image.jpg"
        >

        <label>Stock Quantity</label>

        <input
            type="number"
            name="stock"
            min="0"
            value="{product[7] or 0}"
            placeholder="Example: 10"
        >

        <button type="submit">
            Save Product Changes
        </button>

    </form>

</div>

</body>
</html>
"""
    )


@app.post(
    "/admin/product/edit/{product_id}"
)
def update_product(
    product_id: int,
    name: str = Form(...),
    price: str = Form(""),
    category: str = Form("General"),
    subcategory: str = Form(""),
    description: str = Form(""),
    image_url: str = Form(""),
    stock: str = Form("0")
):

    db = get_db()

    try:

        name = name.strip()
        price = clean_price(price)
        category = category.strip() or "General"
        subcategory = subcategory.strip()
        description = description.strip()
        image_url = image_url.strip()

        try:
            stock_value = max(0, int(stock or 0))
        except (ValueError, TypeError):
            stock_value = 0

        db.execute(
            """
            UPDATE products
            SET
                name = ?,
                price = ?,
                description = ?,
                category = ?,
                subcategory = ?,
                image_url = ?,
                stock = ?
            WHERE id = ?
            """,
            (
                name,
                price,
                description,
                category,
                subcategory,
                image_url,
                stock_value,
                product_id
            )
        )

        db.commit()

    finally:
        db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.get("/admin/product/delete/{product_id}")
def delete_product(product_id: int):

    db = get_db()

    db.execute(
        "DELETE FROM products WHERE id = ?",
        (product_id,)
    )

    db.commit()
    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.post("/admin/order")
def add_order(
    order_number: str = Form(...),
    customer_name: str = Form(...),
    product_name: str = Form(...),
    price: str = Form(""),
    status: str = Form("Pending"),
    expected_delivery: str = Form("")
):
    db = get_db()

    order_number = order_number.strip()
    customer_name = customer_name.strip()
    product_name = product_name.strip()
    price = clean_price(price)
    status = status.strip()
    expected_delivery = expected_delivery.strip()

    # If order price is blank, automatically get
    # price from matching product
    if not price:
        product = db.execute("""
            SELECT price
            FROM products
            WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
            LIMIT 1
        """, (product_name,)).fetchone()

        if product and product[0] not in (None, ""):
            price = clean_price(product[0])

    try:
        db.execute("""
            INSERT INTO orders
            (
                order_number,
                customer_name,
                product_name,
                price,
                status,
                expected_delivery
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            order_number,
            customer_name,
            product_name,
            price,
            status,
            expected_delivery
        ))

        db.commit()

    except sqlite3.IntegrityError:
        db.close()

        return HTMLResponse(
            "Order number already exists. Please use another order number.",
            status_code=400
        )

    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.get("/admin/order/edit/{order_id}", response_class=HTMLResponse)
def edit_order_page(order_id: int):

    db = get_db()

    order = db.execute("""
        SELECT
            id,
            order_number,
            customer_name,
            product_name,
            price,
            status,
            expected_delivery,
            phone,
            address,
            city,
            pincode,
            payment_method,
            payment_status,
            upi_id,
            utr,
            card_holder_name,
            card_last4,
            emi_provider,
            emi_tenure,
            emi_reference,
            created_at
        FROM orders
        WHERE id = ?
    """, (order_id,)).fetchone()

    db.close()

    if not order:
        return HTMLResponse(
            "Order not found",
            status_code=404
        )

    statuses = [
        "Pending",
        "Confirmed",
        "Processing",
        "Shipped",
        "Delivered",
        "Cancelled"
    ]

    status_options = ""

    for status in statuses:

        selected = (
            "selected"
            if status == order[5]
            else ""
        )

        status_options += f"""
        <option value="{html.escape(status)}" {selected}>
            {html.escape(status)}
        </option>
        """

    return f"""
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Edit Order #{html.escape(order[1])}</title>

    <style>

        body {{
            margin: 0;
            min-height: 100vh;
            padding: 30px;
            background: #050816;
            color: white;
            font-family: Arial, sans-serif;
        }}

        .box {{
            max-width: 750px;
            margin: 40px auto;
            padding: 30px;
            background: #111827;
            border-radius: 20px;
        }}

        .box h1 {{
            margin-top: 0;
        }}

        label {{
            display: block;
            margin-top: 18px;
            margin-bottom: 7px;
            color: #cbd5e1;
        }}

        input,
        select,
        textarea {{
            width: 100%;
            padding: 13px;
            border-radius: 10px;
            border: 1px solid #334155;
            background: #0b1220;
            color: white;
            outline: none;
        }}

        textarea {{
            min-height: 90px;
            resize: vertical;
        }}

        option {{
            background: #111827;
            color: white;
        }}

        button {{
            margin-top: 25px;
            padding: 13px 22px;
            border: 0;
            border-radius: 10px;
            background: linear-gradient(135deg, #4f7cff, #764cff);
            color: white;
            cursor: pointer;
            font-weight: bold;
        }}

        .back {{
            display: inline-block;
            margin-bottom: 20px;
            color: #94a3b8;
            text-decoration: none;
        }}

        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
        }}

        @media(max-width: 600px) {{
            .two-col {{
                grid-template-columns: 1fr;
            }}
        }}

    </style>

</head>

<body>

    <div class="box">

        <a class="back" href="/admin">
            ← Back to Dashboard
        </a>

        <h1>✏️ Edit Order #{html.escape(order[1])}</h1>

        <form
            method="post"
            action="/admin/order/edit/{order_id}"
        >

            <label>Order Number</label>

            <input
                name="order_number"
                value="{html.escape(order[1])}"
                required
            >

            <label>Customer Name</label>

            <input
                name="customer_name"
                value="{html.escape(order[2])}"
                required
            >

            <label>Product Name</label>

            <input
                name="product_name"
                value="{html.escape(order[3])}"
                required
            >

            <label>Price</label>

            <input
                name="price"
                value="{html.escape(str(order[4] or ''))}"
                placeholder="Auto-fetch from product"
            >

            <label>Customer Phone</label>

            <input
                name="phone"
                value="{html.escape(order[7] or '')}"
            >

            <label>Delivery Address</label>

            <textarea
                name="address"
            >{html.escape(order[8] or '')}</textarea>

            <label>City</label>

            <input
                name="city"
                value="{html.escape(order[9] or '')}"
            >

            <label>Pincode</label>

            <input
                name="pincode"
                value="{html.escape(order[10] or '')}"
            >

            <div class="two-col">

                <div>

                    <label>Payment Method</label>

                    <select name="payment_method">

                        <option
                            value="UPI"
                            {"selected" if order[11] == "UPI" else ""}
                        >
                            UPI
                        </option>

                        <option
                            value="COD"
                            {"selected" if order[11] == "COD" else ""}
                        >
                            COD
                        </option>

                        <option
                            value="Card"
                            {"selected" if order[11] == "Card" else ""}
                        >
                            Card
                        </option>

                        <option
                            value="EMI"
                            {"selected" if order[11] == "EMI" else ""}
                        >
                            EMI
                        </option>

                    </select>

                </div>

                <div>

                    <label>Payment Status</label>

                    <select name="payment_status">

                        <option
                            value="Pending"
                            {"selected" if order[12] == "Pending" else ""}
                        >
                            Pending
                        </option>

                        <option
                            value="Paid"
                            {"selected" if order[12] == "Paid" else ""}
                        >
                            Paid
                        </option>

                        <option
                            value="Failed"
                            {"selected" if order[12] == "Failed" else ""}
                        >
                            Failed
                        </option>

                        <option
                            value="Refunded"
                            {"selected" if order[12] == "Refunded" else ""}
                        >
                            Refunded
                        </option>

                    </select>

                </div>

            </div>

            <label>UPI ID</label>

            <input
                name="upi_id"
                type="text"
                value="{html.escape(order[13] or '')}"
                placeholder="customer@upi"
            >

            <label>UTR / Transaction ID</label>

            <input
                name="utr"
                type="text"
                value="{html.escape(order[14] or '')}"
                placeholder="UPI transaction ID"
            >

            <label>Cardholder Name</label>

            <input
                name="card_holder_name"
                type="text"
                value="{html.escape(order[15] or '')}"
                placeholder="Name on card"
            >

            <label>Last 4 Digits</label>

            <input
                name="card_last4"
                type="text"
                maxlength="4"
                value="{html.escape(order[16] or '')}"
                placeholder="1234"
            >

            <label>EMI Provider</label>

            <select name="emi_provider">

                <option
                    value=""
                    {"selected" if not order[17] else ""}
                >
                    Select EMI provider
                </option>

                <option
                    value="Bank EMI"
                    {"selected" if order[17] == "Bank EMI" else ""}
                >
                    Bank EMI
                </option>

                <option
                    value="Card EMI"
                    {"selected" if order[17] == "Card EMI" else ""}
                >
                    Card EMI
                </option>

            </select>

            <label>EMI Tenure</label>

            <select name="emi_tenure">

                <option
                    value=""
                    {"selected" if not order[18] else ""}
                >
                    Select tenure
                </option>

                <option
                    value="3 Months"
                    {"selected" if order[18] == "3 Months" else ""}
                >
                    3 Months
                </option>

                <option
                    value="6 Months"
                    {"selected" if order[18] == "6 Months" else ""}
                >
                    6 Months
                </option>

                <option
                    value="9 Months"
                    {"selected" if order[18] == "9 Months" else ""}
                >
                    9 Months
                </option>

                <option
                    value="12 Months"
                    {"selected" if order[18] == "12 Months" else ""}
                >
                    12 Months
                </option>

            </select>

            <label>EMI Reference</label>

            <input
                name="emi_reference"
                type="text"
                value="{html.escape(order[19] or '')}"
                placeholder="Optional reference"
            >

            <label>Order Status</label>

            <select name="status">

                {status_options}

            </select>

            <label>Expected Delivery</label>

            <input
                name="expected_delivery"
                value="{html.escape(order[6] or '')}"
            >

            <button type="submit">
                💾 Save Order Changes
            </button>

        </form>

    </div>

</body>

</html>
"""


@app.post("/admin/order/edit/{order_id}")
def update_order(
    order_id: int,
    order_number: str = Form(...),
    customer_name: str = Form(...),
    product_name: str = Form(...),
    price: str = Form(""),
    status: str = Form("Pending"),
    expected_delivery: str = Form(""),
    phone: str = Form(""),
    address: str = Form(""),
    city: str = Form(""),
    pincode: str = Form(""),
    payment_method: str = Form("UPI"),
    payment_status: str = Form("Pending"),
    upi_id: str = Form(""),
    utr: str = Form(""),
    card_holder_name: str = Form(""),
    card_last4: str = Form(""),
    emi_provider: str = Form(""),
    emi_tenure: str = Form(""),
    emi_reference: str = Form("")
):

    db = get_db()

    try:

        order_number = order_number.strip()
        customer_name = customer_name.strip()
        product_name = product_name.strip()
        price = clean_price(price)
        status = status.strip() or "Pending"
        expected_delivery = expected_delivery.strip()
        phone = phone.strip()
        address = address.strip()
        city = city.strip()
        pincode = pincode.strip()
        payment_method = payment_method.strip() or "UPI"
        payment_status = payment_status.strip() or "Pending"
        upi_id = upi_id.strip()
        utr = utr.strip()
        card_holder_name = card_holder_name.strip()
        card_last4 = card_last4.strip()
        emi_provider = emi_provider.strip()
        emi_tenure = emi_tenure.strip()
        emi_reference = emi_reference.strip()

        # If price is blank, auto-fetch from product
        if not price:
            product = db.execute("""
                SELECT price
                FROM products
                WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
                LIMIT 1
            """, (product_name,)).fetchone()

            if product and product[0] not in (None, ""):
                price = clean_price(product[0])

        db.execute(
            """
            UPDATE orders
            SET
                order_number = ?,
                customer_name = ?,
                product_name = ?,
                price = ?,
                status = ?,
                expected_delivery = ?,
                phone = ?,
                address = ?,
                city = ?,
                pincode = ?,
                payment_method = ?,
                payment_status = ?,
                upi_id = ?,
                utr = ?,
                card_holder_name = ?,
                card_last4 = ?,
                emi_provider = ?,
                emi_tenure = ?,
                emi_reference = ?
            WHERE id = ?
            """,
            (
                order_number,
                customer_name,
                product_name,
                price,
                status,
                expected_delivery,
                phone,
                address,
                city,
                pincode,
                payment_method,
                payment_status,
                upi_id,
                utr,
                card_holder_name,
                card_last4,
                emi_provider,
                emi_tenure,
                emi_reference,
                order_id
            )
        )

        db.commit()

    except sqlite3.IntegrityError:

        db.rollback()

        db.close()

        return HTMLResponse(
            "Order number already exists.",
            status_code=400
        )

    except Exception as error:

        db.rollback()

        print(
            "UPDATE ORDER ERROR:",
            repr(error)
        )

        db.close()

        return HTMLResponse(
            "Unable to update order.",
            status_code=500
        )

    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.get("/admin/order/delete/{order_id}")
def delete_order(order_id: int):

    db = get_db()

    db.execute(
        "DELETE FROM orders WHERE id = ?",
        (order_id,)
    )

    db.commit()

    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.post("/admin/faq")
def add_faq(
    question: str = Form(...),
    answer: str = Form(...)
):

    db = get_db()

    db.execute(
        """
        INSERT INTO faqs
        (question, answer)
        VALUES (?, ?)
        """,
        (
            question.strip(),
            answer.strip()
        )
    )

    db.commit()
    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.get("/admin/faq/delete/{faq_id}")
def delete_faq(faq_id: int):

    db = get_db()

    db.execute(
        "DELETE FROM faqs WHERE id = ?",
        (faq_id,)
    )

    db.commit()
    db.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


# =========================================================
# CHAT
# =========================================================

@app.post("/chat")
def chat(request: ChatRequest):

    message = request.message.strip()

    if not message:
        return {
            "reply": "Please type a message."
        }

    message_lower = message.lower()

    business = get_business()
    products = get_products()
    faqs = get_faqs()

    business_name = business[0] or "My Business"
    business_description = business[1] or ""


    # =====================================================
    # GREETINGS
    # =====================================================

    greetings = {
        "hi",
        "hello",
        "hey",
        "hii",
        "hiii",
        "helo",
        "good morning",
        "good afternoon",
        "good evening"
    }

    if message_lower in greetings:

        return {
            "reply":
                f"Hello! Welcome to {business_name}. "
                "How can I help you today?"
        }


    # =====================================================
    # PRODUCT ENQUIRY
    # =====================================================

    product_enquiry_words = [
        "product",
        "product ke",
        "product ka",
        "details",
        "detail",
        "information",
        "info",
        "about",
        "features",
        "feature",
        "available",
        "availability",
        "price",
        "cost",
        "kitne ka",
        "kitna hai",
        "chahiye",
        "want",
        "looking for"
    ]


    for product in products:

        product_name = product[1] or ""
        product_price = product[2] or ""
        product_description = product[3] or ""

        product_name_lower = product_name.lower()

        # Product name customer message mein hai
        if product_name_lower in message_lower:

            # Product enquiry detect
            is_enquiry = any(
                word in message_lower
                for word in product_enquiry_words
            )

            if is_enquiry:

                return {
                    "reply": (
                        f"📦 {product_name}\n\n"
                        f"💰 Price: ₹{product_price}\n\n"
                        f"📝 Details:\n"
                        f"{product_description}\n\n"
                        f"Is product ke baare mein "
                        f"aur kuch jaanna hai? 😊"
                    )
                }


    # =====================================================
    # SHOW PRODUCTS
    # =====================================================

    show_products_phrases = [
        "show products",
        "show product",
        "show all products",
        "all products",
        "available products",
        "product list",
        "products list",
        "product catalog",
        "product catalogue",
        "catalog",
        "catalogue",
        "what products",
        "what do you sell",
        "what are you selling",
        "available items",
        "all items"
    ]

    if any(
        phrase in message_lower
        for phrase in show_products_phrases
    ):

        if not products:

            return {
                "reply":
                    "We currently don't have any "
                    "products listed."
            }

        lines = [
            "🛍️ Here are our available products:"
        ]

        for product in products:

            name = product[1]
            price = product[2]
            description = product[3]

            lines.append(
                f"• {name} — ₹{price}\n"
                f"  {description}"
            )

        return {
            "reply": "\n\n".join(lines)
        }


    # =====================================================
    # PRICE
    # =====================================================

    price_words = [
        "price",
        "cost",
        "how much",
        "rate",
        "kitne ka",
        "kitna hai",
        "kitne ki",
        "price kya hai"
    ]

    if any(
        word in message_lower
        for word in price_words
    ):

        for product in products:

            product_name = product[1] or ""

            if product_name.lower() in message_lower:

                return {
                    "reply":
                        f"💰 {product_name} "
                        f"costs ₹{product[2]}."
                }

        if products:

            return {
                "reply":
                    "Sure! 😊 Please tell me the "
                    "product name so I can give you "
                    "its exact price."
            }


    # =====================================================
    # ORDER ENQUIRY
    # =====================================================

    order_keywords = [
        "order",
        "order status",
        "my order",
        "order kaha",
        "order kahan",
        "order kab",
        "track order",
        "order track",
        "order check",
        "delivery status",
        "payment status",
        "order details"
    ]

    is_order_question = any(
        keyword in message_lower
        for keyword in order_keywords
    )

    if is_order_question:

        # SKY35188403
        order_match = re.search(
            r"\bSKY\d{8}\b",
            message,
            re.IGNORECASE
        )

        if not order_match:

            return {
                "reply": (
                    "📦 Sure! I can check your order.\n\n"
                    "Please send your order number.\n"
                    "Example: SKY35188403"
                )
            }

        order_number = (
            order_match.group(0)
            .upper()
        )

        order = get_order(order_number)

        if not order:

            return {
                "reply": (
                    f"❌ I couldn't find order "
                    f"#{order_number}.\n\n"
                    "Please check your order ID "
                    "and try again."
                )
            }

        price_value = order[3]

        if price_value:
            try:
                price_display = (
                    f"₹{float(price_value):,.0f}"
                )
            except:
                price_display = f"₹{price_value}"
        else:
            price_display = "Unavailable"

        payment_method = (
            order[10]
            or "Not available"
        )

        payment_status = (
            order[11]
            or "Pending"
        )

        upi_id = (
            order[12]
            or "Not provided"
        )

        utr = (
            order[13]
            or "Not provided"
        )

        delivery = (
            order[5]
            or "Not available"
        )

        return {
            "reply": (
                f"📦 Order #{order[0]}\n\n"

                f"🛍️ Product: {order[2]}\n"
                f"💰 Price: {price_display}\n"
                f"📌 Order Status: {order[4]}\n"
                f"💳 Payment: {payment_method}\n"
                f"💵 Payment Status: {payment_status}\n"
                f"🆔 UPI ID: {upi_id}\n"
                f"🔑 UTR: {utr}\n"
                f"🚚 Expected Delivery: {delivery}\n\n"

                "If you need help with this order, "
                "tell me what problem you're facing."
            )
        }


    # =====================================================
    # FAQ
    # =====================================================

    for faq in faqs:

        question = (faq[1] or "").lower()

        words = [
            word
            for word in question.split()
            if len(word) > 3
        ]

        if not words:
            continue

        matched = 0

        for word in words:

            if word in message_lower:
                matched += 1

        required_matches = min(2, len(words))

        if matched >= required_matches:

            return {
                "reply": faq[2]
            }


    # =====================================================
    # BUSINESS INFORMATION
    # =====================================================

    business_phrases = [
        "about business",
        "about your business",
        "about company",
        "about your company",
        "who are you",
        "what do you do",
        "tell me about business",
        "tell me about your business"
    ]

    if any(
        phrase in message_lower
        for phrase in business_phrases
    ):

        return {
            "reply": (
                f"🏪 {business_name}\n\n"
                f"{business_description}"
            )
        }


    # =====================================================
    # GEMINI AI
    # =====================================================

    if gemini_client is not None:

        try:

            product_context = "\n".join(
                f"- {p[1]} | Price: ₹{p[2]} | {p[3]}"
                for p in products
            )

            faq_context = "\n".join(
                f"- Question: {f[1]}\n"
                f"  Answer: {f[2]}"
                for f in faqs
            )

            business_context = (
                f"Business name: {business_name}\n\n"
                f"Business description: "
                f"{business_description}\n\n"
                f"Products:\n"
                f"{product_context or 'No products listed.'}\n\n"
                f"FAQs:\n"
                f"{faq_context or 'No FAQs listed.'}"
            )

            prompt = f"""
You are an AI customer-support assistant
for a business.

BUSINESS INFORMATION
====================

{business_context}


CUSTOMER MESSAGE
================

{message}


RULES
=====

1. Answer naturally and politely.

2. Keep the answer concise and useful.

3. Use the business information provided above.

4. Never invent products.

5. Never invent prices.

6. Never invent discounts.

7. Never invent policies.

8. Never invent services.

9. If information is unavailable,
say that you don't have that information.

10. If the customer asks about a product,
use the exact product information provided.

11. Never change a product's price.

12. Do not claim that an order was placed.

13. Answer in the same language used
by the customer when practical.

14. Be friendly and professional.
"""

            response = gemini_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )

            answer = response.text

            if not answer:

                answer = (
                    "Sorry, I couldn't generate "
                    "a response right now."
                )

            return {
                "reply": answer
            }

        except Exception as error:

            print("Gemini error:", repr(error))

            return {
                "reply":
                    "Sorry! I'm having trouble "
                    "processing that right now. "
                    "Please try again."
            }


    # =====================================================
    # NO API FALLBACK
    # =====================================================

    return {
        "reply": (
            f"Thanks for contacting {business_name}! 🤖\n\n"
            "I don't have an answer for that yet.\n"
            "Please contact the business for more information."
        )
    }