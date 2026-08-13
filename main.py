import os
import sqlite3
import re
import html
import time
import hmac
import hashlib

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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


app = FastAPI(title="AI Business Assistant")


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


init_db()


# =========================================================
# MODELS
# =========================================================

class ChatRequest(BaseModel):
    message: str


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
        SELECT id, name, price, description
        FROM products
        ORDER BY id DESC
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
    result = db.execute("""
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
            o.expected_delivery
        FROM orders o
        LEFT JOIN products p
            ON LOWER(TRIM(o.product_name))
             = LOWER(TRIM(p.name))
        ORDER BY o.id DESC
    """).fetchall()
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
            expected_delivery
        FROM orders
        WHERE order_number = ?
    """, (order_number,)).fetchone()

    if not order:
        db.close()
        return None

    # Order price blank hai to product price use karo
    price = order[3]

    if price is None or str(price).strip() == "":
        product = db.execute("""
            SELECT price
            FROM products
            WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
            LIMIT 1
        """, (order[2],)).fetchone()

        if product and product[0] not in (None, ""):
            price = product[0]

    db.close()

    # Same tuple structure rakho
    return (
        order[0],
        order[1],
        order[2],
        price,
        order[4],
        order[5]
    )


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

.quick {
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    padding: 0 30px 20px;
}

.quick a {
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

.quick a:hover {
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

    .quick {
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

            <a
                href="/admin"
                style="
                    color:#64748b;
                    text-decoration:none;
                    font-size:12px;
                "
            >
                ⚙️ Business Admin
            </a>

        </div>

    </aside>


    <main class="main">


        <header class="header">

            <div>
                <h1>AI Business Assistant</h1>

                <p>
                    Your intelligent customer support
                </p>
            </div>

            <div class="badge">
                ● AI Online
            </div>

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


        <div class="quick">

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
}


async function sendMessage() {

    const text =
        input.value.trim();

    if (!text) return;


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


# =========================================================
# PREMIUM CUSTOMER PAGES
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

    padding: 18px 22px;

    border-radius: 22px;

    background:
        rgba(255,255,255,.06);

    border:
        1px solid rgba(255,255,255,.1);

    backdrop-filter:
        blur(30px);
}}

.topbar h1 {{

    margin: 0;

    font-size: 20px;
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
        repeat(auto-fill,minmax(260px,1fr));

    gap: 18px;
}}

.card {{

    padding: 22px;

    border-radius: 24px;

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

    font-size: 18px;
}}

.card p {{

    color: #94a3b8;

    line-height: 1.6;

    font-size: 13px;
}}

.price {{

    font-size: 20px;

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
}}

.empty {{

    text-align: center;

    padding: 60px 20px;

    color: #64748b;
}}

@media(max-width:650px) {{

    body {{
        padding: 15px;
    }}

    .topbar {{
        padding: 15px;
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

            cards += f"""
            <div class="card">

                <div class="icon">
                    📦
                </div>

                <h2>{product[1]}</h2>

                <div class="price">
                    ₹{product[2]}
                </div>

                <p>
                    {product[3]}
                </p>

                <a
                    class="btn"
                    href="/products/{product[0]}"
                >
                    View Details →
                </a>

            </div>
            """

        content = f"""
        <div class="grid">
            {cards}
        </div>
        """

    return page_shell(
        "🛍️ Products",
        content
    )


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
                This product does not exist.
            </div>
            """
        )

    content = f"""
    <div class="card">

        <div class="icon">
            📦
        </div>

        <h2>{product[1]}</h2>

        <div class="price">
            ₹{product[2]}
        </div>

        <p>
            {product[3]}
        </p>

        <br>

        <a class="btn" href="/support">
            Need Help? →
        </a>

    </div>
    """

    return page_shell(
        f"📦 {product[1]}",
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
                "Delivered"
            ]

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

            for index, status in enumerate(statuses):

                if index < status_index:
                    state = "done"
                    icon = "✓"

                elif index == status_index:
                    state = "active"
                    icon = "●"

                else:
                    state = "waiting"
                    icon = "○"

                timeline += f"""
                <div class="timeline-item {state}">

                    <div class="timeline-dot">
                        {icon}
                    </div>

                    <div class="timeline-content">
                        <div class="timeline-title">
                            {html.escape(status)}
                        </div>
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
                min-height:62px;
                animation:fadeIn .3s ease;
            }}

            @keyframes fadeIn {{
                from {{ opacity:0; transform:translateY(5px); }}
                to {{ opacity:1; transform:translateY(0); }}
            }}

            .timeline-item:not(:last-child)::after {{
                content:"";
                position:absolute;
                left:12px;
                top:27px;
                width:2px;
                height:40px;
                background:rgba(255,255,255,.10);
            }}

            .timeline-dot {{
                width:26px;
                height:26px;
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

            .timeline-content {{
                padding-top:3px;
            }}

            .timeline-title {{
                font-size:13px;
                color:#64748b;
                transition:.3s;
            }}

            .timeline-item.done .timeline-dot {{
                background:rgba(34,197,94,.12);
                border-color:rgba(34,197,94,.25);
                color:#4ade80;
            }}

            .timeline-item.done .timeline-title {{
                color:#cbd5e1;
            }}

            .timeline-item.done:not(:last-child)::after {{
                background:rgba(34,197,94,.15);
            }}

            .timeline-item.active .timeline-dot {{
                background:rgba(79,124,255,.18);
                border-color:rgba(79,124,255,.45);
                color:#93c5fd;
                box-shadow:
                    0 0 18px rgba(79,124,255,.25);
                animation:pulse 2s infinite;
            }}

            @keyframes pulse {{
                0% {{ box-shadow: 0 0 18px rgba(79,124,255,.25); }}
                50% {{ box-shadow: 0 0 30px rgba(79,124,255,.4); }}
                100% {{ box-shadow: 0 0 18px rgba(79,124,255,.25); }}
            }}

            .timeline-item.active .timeline-title {{
                color:white;
                font-weight:600;
            }}

            .timeline-item.waiting .timeline-title {{
                color:#475569;
            }}

            .timeline-item.waiting .timeline-dot {{
                color:#475569;
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
    <div class="grid">

        <div class="card">

            <div class="icon">
                🤖
            </div>

            <h2>AI Customer Support</h2>

            <p>
                Ask our AI assistant about products,
                prices, orders and business information.
            </p>

            <a class="btn" href="/">
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
                    ❓ {faq[1]}
                </h2>

                <p>
                    {faq[2]}
                </p>

            </div>
            """

        content = f"""
        <div class="grid">
            {cards}
        </div>
        """

    return page_shell(
        "❓ Frequently Asked Questions",
        content
    )


@app.get("/about", response_class=HTMLResponse)
def about_page():

    business = get_business()

    content = f"""
    <div class="card">

        <div class="icon">
            🏪
        </div>

        <h2>{business[0]}</h2>

        <p>
            {business[1]}
        </p>

    </div>
    """

    return page_shell(
        "🏪 About Our Business",
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

    business_name = html.escape(business[0] or "")
    business_description = html.escape(business[1] or "")

    product_count = len(products)
    faq_count = len(faqs)
    order_count = len(orders)

    # -----------------------------------------------------
    # PRODUCTS
    # -----------------------------------------------------

    products_html = ""

    for product in products:

        product_id = product[0]
        name = html.escape(product[1] or "")
        price = html.escape(str(product[2] or ""))
        description = html.escape(product[3] or "")

        products_html += f"""
        <div class="product-card">

            <div class="product-icon">
                📦
            </div>

            <div class="product-info">

                <div class="product-title">
                    {name}
                </div>

                <div class="product-price">
                    ₹{price}
                </div>

                <div class="product-description">
                    {description}
                </div>

            </div>

            <a
                class="delete-btn"
                href="/admin/product/delete/{product_id}"
                onclick="return confirm('Delete this product?')"
            >
                Delete
            </a>

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

                <div class="product-description">
                    👤 {customer_name}
                    &nbsp; • &nbsp;
                    📌 {status}
                    &nbsp; • &nbsp;
                    🚚 {delivery}
                </div>

            </div>

            <div style="display:flex;gap:6px;align-items:center;">

                <a
                    href="/admin/order/edit/{order_id}"
                    style="
                        color:#93c5fd;
                        text-decoration:none;
                        font-size:10px;
                        padding:8px 10px;
                        border-radius:10px;
                        background:rgba(79,124,255,.08);
                        border:1px solid rgba(79,124,255,.12);
                    "
                >
                    ✏️ Edit
                </a>

                <a
                    class="delete-btn"
                    href="/admin/order/delete/{order_id}"
                    onclick="return confirm('Delete this order?')"
                >
                    Delete
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

        <div class="stats">


            <div class="stat">

                <div class="stat-icon">
                    📦
                </div>

                <div class="stat-number">
                    {product_count}
                </div>

                <div class="stat-label">
                    Total Products
                </div>

            </div>


            <div class="stat">

                <div class="stat-icon">
                    ❓
                </div>

                <div class="stat-number">
                    {faq_count}
                </div>

                <div class="stat-label">
                    Total FAQs
                </div>

            </div>


            <div class="stat">

                <div class="stat-icon">
                    📦
                </div>

                <div class="stat-number">
                    {order_count}
                </div>

                <div class="stat-label">
                    Total Orders
                </div>

            </div>


            <div class="stat">

                <div class="stat-icon">
                    🤖
                </div>

                <div class="stat-number">
                    Online
                </div>

                <div class="stat-label">
                    AI Assistant Status
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
                    placeholder="Example: Gaming Laptop"
                    required
                >


                <label>
                    Price
                </label>

                <input
                    name="price"
                    placeholder="65000"
                >


                <label>
                    Description
                </label>

                <textarea
                    name="description"
                    placeholder="Product description"
                ></textarea>


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


@app.post("/admin/product")
def add_product(
    name: str = Form(...),
    price: str = Form(""),
    description: str = Form("")
):

    db = get_db()

    db.execute(
        """
        INSERT INTO products
        (name, price, description)
        VALUES (?, ?, ?)
        """,
        (
            name.strip(),
            clean_price(price),
            description.strip()
        )
    )

    db.commit()
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
            expected_delivery
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
            margin:0;
            min-height:100vh;
            padding:30px;
            font-family:Arial,sans-serif;
            color:white;
            background:
                radial-gradient(
                    circle at 20% 10%,
                    rgba(79,124,255,.22),
                    transparent 30%
                ),
                #070b16;
        }}

        .box {{
            max-width:650px;
            margin:40px auto;
            padding:30px;
            border-radius:25px;
            background:rgba(255,255,255,.06);
            border:1px solid rgba(255,255,255,.12);
            backdrop-filter:blur(25px);
        }}

        h1 {{
            margin-top:0;
        }}

        label {{
            display:block;
            margin:
                16px 0 7px;
            color:#aab5c8;
            font-size:13px;
        }}

        input,
        select {{
            width:100%;
            padding:13px;
            border-radius:12px;
            border:1px solid rgba(255,255,255,.1);
            background:rgba(255,255,255,.05);
            color:white;
            outline:none;
        }}

        option {{
            background:#111827;
            color:white;
        }}

        button {{
            margin-top:22px;
            padding:13px 20px;
            border:0;
            border-radius:12px;
            color:white;
            cursor:pointer;
            background:
                linear-gradient(
                    135deg,
                    #4f7cff,
                    #764cff
                );
        }}

        .back {{
            display:inline-block;
            margin-bottom:20px;
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

            <h1>
                📦 Edit Order #{html.escape(order[1])}
            </h1>

            <form
                method="post"
                action="/admin/order/edit/{order_id}"
            >

                <label>
                    Order Number
                </label>

                <input
                    name="order_number"
                    value="{html.escape(order[1])}"
                    required
                >

                <label>
                    Customer Name
                </label>

                <input
                    name="customer_name"
                    value="{html.escape(order[2])}"
                    required
                >

                <label>
                    Product
                </label>

                <input
                    name="product_name"
                    value="{html.escape(order[3])}"
                    required
                >

                <label>
                    Price
                </label>

                <input
                    name="price"
                    value="{html.escape(str(order[4] or ""))}"
                    placeholder="Auto-fetch from product if left blank"
                    style="color:#94a3b8;"
                >

                <label>
                    Order Status
                </label>

                <select name="status">

                    {status_options}

                </select>

                <label>
                    Expected Delivery
                </label>

                <input
                    name="expected_delivery"
                    value="{html.escape(order[6] or "")}"
                >

                <button type="submit">
                    Save Order Changes
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
    expected_delivery: str = Form("")
):

    db = get_db()

    order_number = order_number.strip()
    customer_name = customer_name.strip()
    product_name = product_name.strip()
    price = clean_price(price)
    status = status.strip()
    expected_delivery = expected_delivery.strip()

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

    try:
        db.execute("""
            UPDATE orders
            SET
                order_number = ?,
                customer_name = ?,
                product_name = ?,
                price = ?,
                status = ?,
                expected_delivery = ?
            WHERE id = ?
        """, (
            order_number,
            customer_name,
            product_name,
            price,
            status,
            expected_delivery,
            order_id
        ))

        db.commit()

    except sqlite3.IntegrityError:
        db.close()
        return HTMLResponse(
            "Order number already exists.",
            status_code=400
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
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return CHAT_PAGE


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
        "delivery status"
    ]

    is_order_question = any(
        keyword in message_lower
        for keyword in order_keywords
    )

    if is_order_question:

        # Find order number like:
        # Order #1001
        # Order 1001
        # order no 1001
        # order number 1001

        order_match = re.search(
            r"(?:order\s*(?:#|no\.?|number)?\s*)(\d+)",
            message_lower
        )

        if not order_match:

            return {
                "reply": (
                    "📦 Sure! I can check your order status.\n\n"
                    "Please send your order number.\n"
                    "Example: Order #1001"
                )
            }

        order_number = order_match.group(1)

        order = get_order(order_number)

        if not order:

            return {
                "reply": (
                    f"❌ I couldn't find order #{order_number}.\n\n"
                    "Please check the order number and try again."
                )
            }

        # Format price for AI response
        price_val = order[3]
        if price_val is None:
            price_display = "Price unavailable"
        else:
            price_text = str(price_val).strip()
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

        return {
            "reply": (
                f"📦 Order #{order[0]}\n\n"
                f"🛍️ Product: {order[2]}\n"
                f"💰 Price: {price_display}\n"
                f"📌 Status: {order[4]}\n"
                f"🚚 Expected delivery: {order[5] or 'Not available'}"
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