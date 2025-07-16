from flask import Flask, render_template, request, g, redirect, session, url_for, flash, jsonify, current_app
import sqlite3, os, json, random, string, smtplib, ssl, time, razorpay
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask_login import LoginManager, current_user, login_required, logout_user

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.permanent_session_lifetime = timedelta(days=100)

client = razorpay.Client(auth=("rzp_live_8teFtytXqXhxwa", "wv24XQhmouaxsoyPJ2F2hAX4"))

APP_NAME = "Yash Cyber Cafe"
EMAIL_ADDRESS = "yashcybercafeofficial@gmail.com"
EMAIL_PASSWORD = "jgwujcylyefeaefz"

def generate_random_otp(length=6):
    import random
    return ''.join(random.choices('0123456789', k=length))

def send_otp_to_email(email, otp):
    import smtplib, ssl

    subject = f"{APP_NAME} - OTP Verification"
    body = f"""Hello,

Your OTP for {APP_NAME} is: {otp}

This code is valid for 5 minutes. Please do not share it with anyone.

Regards,
{APP_NAME} Team
"""

    # Add custom From header (may be ignored by Gmail)
    message = f"From: {APP_NAME} <{EMAIL_ADDRESS}>\nSubject: {subject}\n\n{body}"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, message)
        return True
    except Exception as e:
        print("OTP send error:", e)
        return False

def fetch_all(db_name, table_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except:
        return []
    finally:
        conn.close()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("users.db", timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def get_users_db():
    conn = sqlite3.connect("users.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_admins_db():
    conn = sqlite3.connect("admins.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_products_db():
    conn = sqlite3.connect('products.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_cart_db():
    conn = sqlite3.connect("cart.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_orders_db():
    conn = sqlite3.connect("orders.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def utc_to_local(utc_str):
    utc_time = datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("UTC"))
    local_time = utc_time.astimezone(ZoneInfo("Asia/Kolkata"))
    return local_time.strftime("%d/%m/%y %I:%M %p")

@app.template_filter('datetimeformat')
def format_datetime(value):
    try:
        utc = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        ist = utc + timedelta(hours=5, minutes=30)
        return ist.strftime("%d/%m/%Y %I:%M %p")
    except Exception:
        return value

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

def get_user():
    user_id = session.get("user_id")
    user_meta = session.get("user")

    if not user_id or not user_meta:
        return None

    role = user_meta.get("role")
    if role in ("admin", "seller", "owner"):
        conn = sqlite3.connect("admins.db")
        table = "admins"
    else:
        conn = sqlite3.connect("users.db")
        table = "users"

    conn.row_factory = sqlite3.Row
    row = conn.execute(
        f"""
        SELECT id, full_name, email, profile_image, role, contact, gender_id
        FROM {table}
        WHERE id = ?
        """, (user_id,)
    ).fetchone()
    conn.close()

    return dict(row) if row else None

def handle_login(expected_role):
    email = request.form.get("email")
    password = request.form.get("password")

    conn = get_users_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        if user["role"] != expected_role:
            flash("Invalid login for this portal.", "error")
            return redirect(request.path)

        session["user_id"] = user["id"]
        flash("Logged in successfully!", "success")
        return redirect(url_for("seller_dashboard"))

    flash("Invalid credentials", "error")
    return redirect(request.path)

def get_owner_id():
    conn = get_admins_db()
    cursor = conn.execute("SELECT id FROM admins WHERE role = 'owner' LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result['id'] if result else None

# users route ====users route=======users route=============users route=============users route===================users route=============users route================users route=================users route=

@app.route("/")
def user_home():
    user = get_user()
    conn = get_products_db()
    cursor = conn.execute("SELECT id, name, price, discount_price, images FROM product")
    
    product_items = []
    for row in cursor.fetchall():
        # Normalize image field
        try:
            images = json.loads(row["images"]) if row["images"].strip().startswith("[") else [row["images"]]
        except Exception:
            images = [row["images"]] if row["images"] else []

        try:
            discount_price = float(row['discount_price']) if row['discount_price'] not in (None, '', 'None') else 0.0
        except Exception:
            discount_price = 0.0

        product_items.append({
            'id': row['id'],
            'name': row['name'],
            'price': float(row['price']),
            'discount_price': discount_price,
            'images': images
        })

    conn.close()

    # ✅ Check if it's an API request
    accept_type = request.headers.get("Accept", "")
    if "application/json" in accept_type:
        return jsonify({
            "user": {
                "id": user.get("id"),
                "name": user.get("full_name")
            } if user else None,
            "products": product_items
        })

    # ✅ Else: normal HTML render for web
    return render_template(
        "user_home.html",
        user=user,
        full_name=user["full_name"] if user else None,
        product_items=product_items
    )

@app.route("/user_shop")
def user_shop():
    user = get_user()

    # Redirect seller to dashboard
    if user and user.get("role") == "seller":
        return redirect(url_for("seller_dashboard"))

    query = request.args.get("q", "").strip().lower()

    conn = get_products_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT id, name, price, discount_price, images, description FROM product")

    product_items = []
    for row in cursor.fetchall():
        name = row["name"] or ""
        description = row["description"] or ""

        # 🔍 Search filter
        if query and query not in name.lower() and query not in description.lower():
            continue

        # 🖼️ Parse images
        raw_images = row["images"]
        try:
            images = json.loads(raw_images) if raw_images and raw_images.strip().startswith("[") else [raw_images]
        except Exception:
            images = [raw_images] if raw_images else []

        # 💸 Handle discount
        try:
            discount_price = float(row["discount_price"]) if row["discount_price"] not in (None, '', 'None') else 0.0
        except Exception:
            discount_price = 0.0

        product_items.append({
            'id': row['id'],
            'name': name,
            'price': float(row['price']),
            'discount_price': discount_price,
            'images': images
        })

    conn.close()

    # 🔁 Return JSON for app (API)
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify({
            "user": {
                "id": user.get("id"),
                "name": user.get("full_name")
            } if user else None,
            "query": query,
            "products": product_items
        })

    # 🌐 Else: Render HTML for web
    return render_template(
        "user_shop.html",
        user=user,
        full_name=user.get("full_name") if user else None,
        product_items=product_items,
        query=query
    )

@app.route('/user_products_details/<int:product_id>')
def user_products_details(product_id):
    user = get_user()

    # ✅ Seller redirect
    if user and user.get("role") == "seller":
        return redirect(url_for("seller_dashboard"))

    # ✅ Fetch product
    conn = get_products_db()
    conn.row_factory = sqlite3.Row
    product = conn.execute('SELECT * FROM product WHERE id = ?', (product_id,)).fetchone()
    conn.close()

    if not product:
        return redirect(url_for('user_shop'))

    # ✅ Parse images
    try:
        images_raw = product["images"]
        if images_raw and images_raw.strip().startswith("["):
            images = json.loads(images_raw)
        else:
            images = [img.strip() for img in images_raw.split(',') if img.strip()]
    except Exception:
        images = []

    # ✅ Prepare product data
    product_data = {
        'id': product['id'],
        'name': product['name'],
        'description': product['description'] if product['description'] else '',
        'price': float(product['price']),
        'discount_price': float(product['discount_price']) if product['discount_price'] not in (None, '', 'None') else 0.0,
        'images': images
    }

    # ✅ Return JSON for App clients
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify(product_data)

    # ✅ Else: Render Web page
    return render_template(
        'user_products_details.html',
        product=product_data,
        user=user
    )

@app.route('/user_checkout', defaults={'product_id': None})
@app.route('/user_checkout/<int:product_id>')
def user_checkout(product_id):
    user = get_user()

    # ✅ Redirect seller users
    if user and user.get("role") == "seller":
        return redirect(url_for("seller_dashboard"))

    # ✅ Unauthenticated or invalid role
    if not user or user.get("role") != "user":
        flash("Please log in to continue.", "login_error")
        ua = request.headers.get('User-Agent', '').lower()
        if any(x in ua for x in ["mobi", "android", "iphone"]):
            return redirect("/user_shop")
        return redirect(url_for("user_home"))

    cart = []
    subtotal = 0
    shipping_fee = 0  # Change if you want to charge

    # ✅ Buy Now flow
    if product_id:
        conn = get_products_db()
        product = conn.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
        conn.close()

        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("user_shop"))

        try:
            images = json.loads(product["images"]) if product["images"].strip().startswith("[") else [
                img.strip() for img in product["images"].split(",") if img.strip()
            ]
        except:
            images = []

        price = float(product["discount_price"] or product["price"] or 0)

        cart.append({
            "id": product["id"],
            "name": product["name"],
            "description": product["description"],
            "price": price,
            "qty": 1,
            "images": images
        })
        subtotal = price

    # ✅ Cart checkout flow
    else:
        user_id = user["id"]
        cart_conn = get_cart_db()
        product_conn = get_products_db()

        cart_items = cart_conn.execute("SELECT * FROM cart WHERE user_id = ?", (user_id,)).fetchall()

        for item in cart_items:
            product = product_conn.execute("SELECT * FROM product WHERE id = ?", (item["product_id"],)).fetchone()
            if product:
                price = float(product["discount_price"] or product["price"] or 0)
                cart.append({
                    "id": product["id"],
                    "name": product["name"],
                    "price": price,
                    "qty": item["quantity"]
                })
                subtotal += price * item["quantity"]

        product_conn.close()
        cart_conn.close()

        if not cart:
            flash("Your cart is empty.", "error")
            return redirect(url_for("user_cart"))

    total = subtotal + shipping_fee

    return render_template(
        "user_checkout.html",
        user=user,
        cart=cart,
        subtotal=subtotal,
        shipping_fee=shipping_fee,
        total=total
    )

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    user = get_user()

    # ✅ User not logged in
    if not user or user.get("role") != "user":
        return jsonify({"message": "Please log in to add items to cart."}), 401

    user_id = user["id"]
    conn = get_cart_db()

    # ✅ Check if item already in cart
    existing = conn.execute(
        "SELECT * FROM cart WHERE user_id = ? AND product_id = ?", (user_id, product_id)
    ).fetchone()

    if existing:
        conn.execute("UPDATE cart SET quantity = quantity + 1 WHERE id = ?", (existing["id"],))
    else:
        conn.execute(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
            (user_id, product_id, 1)
        )

    conn.commit()
    conn.close()

    return jsonify({"message": "Item added to cart successfully!"})

@app.route("/user_cart")
def user_cart():
    user = get_user()

    if not user or user.get("role") != "user":
        flash("Please log in to view your cart.", "login_error")
        ua = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in ua or "android" in ua or "iphone" in ua
        return redirect("/user_shop" if is_mobile else url_for("user_home"))

    user_id = user["id"]
    cart_conn = get_cart_db()
    product_conn = get_products_db()
    cart_items = cart_conn.execute("SELECT * FROM cart WHERE user_id = ?", (user_id,)).fetchall()

    enriched_items = []
    for item in cart_items:
        product = product_conn.execute("SELECT * FROM product WHERE id = ?", (item["product_id"],)).fetchone()
        if product:
            price = float(product["discount_price"]) if product["discount_price"] else float(product["price"])
            total = price * item["quantity"]

            try:
                images = json.loads(product["images"]) if product["images"].strip().startswith("[") else product["images"].split(",")
                image = images[0].strip() if images else "default.jpg"
            except:
                image = "default.jpg"

            enriched_items.append({
                "cart_id": item["id"],
                "product_id": product["id"],
                "name": product["name"],
                "price": price,
                "quantity": item["quantity"],
                "total": total,
                "image": image
            })

    subtotal = sum(item["total"] for item in enriched_items)
    shipping = 0 if enriched_items else 0
    grand_total = subtotal + shipping

    if request.headers.get("Accept") == "application/json":
        return jsonify({
            "cart": enriched_items,
            "subtotal": subtotal,
            "shipping": shipping,
            "total": grand_total
        })

    return render_template(
        "user_cart.html",
        user=user,
        cart=enriched_items,
        subtotal=subtotal,
        shipping=shipping,
        total=grand_total
    )

@app.route('/update_cart/<int:cart_id>', methods=['POST'])
def update_cart(cart_id):
    user = get_user()
    if not user or user.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 401

    action = request.form.get("action") or request.json.get("action")
    conn = get_cart_db()
    item = conn.execute("SELECT * FROM cart WHERE id = ? AND user_id = ?", (cart_id, user["id"])).fetchone()

    if not item:
        conn.close()
        return jsonify({"error": "Item not found"}), 404

    if action == "increase":
        conn.execute("UPDATE cart SET quantity = quantity + 1 WHERE id = ?", (cart_id,))
    elif action == "decrease" and item["quantity"] > 1:
        conn.execute("UPDATE cart SET quantity = quantity - 1 WHERE id = ?", (cart_id,))
    elif action == "decrease":
        conn.execute("DELETE FROM cart WHERE id = ?", (cart_id,))
    else:
        conn.close()
        return jsonify({"error": "Invalid action"}), 400

    conn.commit()
    conn.close()

    if request.headers.get("Accept") == "application/json":
        return jsonify({"success": True})

    return redirect(url_for("user_cart"))

@app.route('/remove_from_cart/<int:cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    user = get_user()
    if not user or user.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_cart_db()
    conn.execute("DELETE FROM cart WHERE id = ? AND user_id = ?", (cart_id, user["id"]))
    conn.commit()
    conn.close()

    if request.headers.get("Accept") == "application/json":
        return jsonify({"success": True})

    return redirect(url_for("user_cart"))

@app.route("/place_cod_order", methods=["POST"])
def place_cod_order():
    user = get_user()
    if not user or user.get("role") != "user":
        if request.headers.get("Content-Type") == "application/json":
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("user_home"))

    data = request.get_json() if request.is_json else request.form

    # Extract address & payment info
    name = data.get("full_name", "").strip()
    phone = data.get("phone", "").strip()
    address1 = data.get("address1", "").strip()
    address2 = data.get("address2", "").strip()
    city = data.get("city", "").strip()
    state = data.get("state", "").strip()
    zip_code = data.get("zip", "").strip()
    country = data.get("country", "").strip()
    payment_method = data.get("payment_method", "cod")

    if not all([name, phone, address1, city, state, zip_code, country]):
        if request.is_json:
            return jsonify({"error": "Missing required address fields."}), 400
        flash("Please fill in all required address fields.", "error")
        return redirect(url_for("user_cart"))

    created_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    user_id = user["id"]
    user_email = user["email"]

    cart_conn = get_cart_db()
    product_conn = get_products_db()
    cart_items = cart_conn.execute("SELECT * FROM cart WHERE user_id = ?", (user_id,)).fetchall()

    items_to_order = []

    if cart_items:
        for item in cart_items:
            product = product_conn.execute("SELECT * FROM product WHERE id = ?", (item["product_id"],)).fetchone()
            if not product:
                continue
            qty = item["quantity"]
            price = float(product["discount_price"]) if product["discount_price"] else float(product["price"])
            total = qty * price

            try:
                images = json.loads(product["images"]) if product["images"].strip().startswith("[") else product["images"].split(",")
                image = images[0].strip() if images else "default.jpg"
            except:
                image = "default.jpg"

            seller_id = product.get("seller_id", 1)

            items_to_order.append({
                "item_id": product["id"],
                "item_name": product["name"],
                "qty": qty,
                "amount": total,
                "image": image,
                "seller_id": seller_id
            })

    else:
        try:
            product_id = int(data.get("product_id"))
            qty = int(data.get("qty", 1))
            product = product_conn.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
            if not product:
                msg = "Product not found."
                return jsonify({"error": msg}) if request.is_json else redirect(url_for("user_shop"))

            price = float(product["discount_price"]) if product["discount_price"] else float(product["price"])
            total = qty * price

            try:
                images = json.loads(product["images"]) if product["images"].strip().startswith("[") else product["images"].split(",")
                image = images[0].strip() if images else "default.jpg"
            except:
                image = "default.jpg"

            seller_id = product.get("seller_id", 1)

            items_to_order = [{
                "item_id": product_id,
                "item_name": product["name"],
                "qty": qty,
                "amount": total,
                "image": image,
                "seller_id": seller_id
            }]
        except:
            msg = "Invalid product or quantity."
            return jsonify({"error": msg}) if request.is_json else redirect(url_for("user_shop"))

    # ✅ Save to orders
    conn_orders = get_orders_db()
    for item in items_to_order:
        conn_orders.execute("""
            INSERT INTO orders (
                item_id, item_name, quantity, amount, status,
                address1, address2, city, pincode, order_date,
                user_id, user_name, user_contact, user_email, image,
                created_at, seller_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["item_id"], item["item_name"], item["qty"], item["amount"], "pending",
            address1, address2, city, zip_code, created_at,
            user_id, name, phone, user_email, item["image"],
            created_at, item["seller_id"]
        ))
    conn_orders.commit()
    conn_orders.close()

    # ✅ Empty cart
    if cart_items:
        cart_conn.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))
        cart_conn.commit()

    if request.is_json:
        return jsonify({"success": True, "message": "COD order placed successfully."})

    flash("Your COD order has been placed!", "success")
    return redirect(url_for("user_orders"))

@app.route("/place_online_order", methods=["POST"])
def place_online_order():
    user = get_user()
    if not user or user.get("role") != "user":
        if request.is_json:
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("user_home"))

    data = request.get_json() if request.is_json else request.form

    name = data.get("full_name", "").strip()
    phone = data.get("phone", "").strip()
    address1 = data.get("address1", "").strip()
    address2 = data.get("address2", "").strip()
    city = data.get("city", "").strip()
    state = data.get("state", "").strip()
    zip_code = data.get("zip", "").strip()
    country = data.get("country", "").strip()
    payment_id = data.get("razorpay_payment_id", "").strip()

    if not all([name, phone, address1, city, state, zip_code, country, payment_id]):
        if request.is_json:
            return jsonify({"error": "Missing required fields."}), 400
        return redirect(url_for("user_checkout"))

    user_id = user["id"]
    user_email = user.get("email", "")
    created_at = datetime.now().strftime("%d %b %Y, %I:%M %p")

    cart_conn = get_cart_db()
    product_conn = get_products_db()
    order_conn = get_orders_db()

    cart_items = cart_conn.execute("SELECT * FROM cart WHERE user_id = ?", (user_id,)).fetchall()
    if not cart_items:
        if request.is_json:
            return jsonify({"error": "Cart is empty."}), 400
        flash("Your cart is empty!", "error")
        return redirect(url_for("user_shop"))

    for item in cart_items:
        product = product_conn.execute("SELECT * FROM product WHERE id = ?", (item["product_id"],)).fetchone()
        if not product:
            continue

        quantity = item["quantity"]
        price = float(product["discount_price"]) if product["discount_price"] else float(product["price"])
        total_amount = quantity * price

        # ✅ Parse image
        try:
            raw = product["images"]
            images = json.loads(raw) if raw.strip().startswith("[") else [i.strip() for i in raw.split(",") if i.strip()]
            image = images[0] if images else "default.jpg"
        except:
            image = "default.jpg"

        seller_id = product.get("seller_id", 1)

        order_conn.execute("""
            INSERT INTO orders (
                item_id, item_name, quantity, amount, status,
                address1, address2, city, pincode, order_date,
                user_id, user_name, user_contact, user_email, image,
                created_at, seller_id, payment_id, is_paid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            product["id"], product["name"], quantity, total_amount, "accepted",
            address1, address2, city, zip_code, created_at,
            user_id, name, phone, user_email, image,
            created_at, seller_id, payment_id, 1
        ))

    order_conn.commit()
    order_conn.close()

    cart_conn.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))
    cart_conn.commit()
    cart_conn.close()

    if request.is_json:
        return jsonify({"success": True, "message": "Payment successful and order placed."})

    flash("✅ Payment successful! Your order has been placed.", "success")
    return redirect(url_for("user_orders"))

@app.route('/create_payment', methods=["POST"])
def create_payment():
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    total = float(data.get("total", 0))
    if total <= 0:
        return jsonify({"error": "Invalid total"}), 400

    try:
        amount_in_paise = int(total * 100)

        razorpay_order = client.order.create({
            "amount": amount_in_paise,
            "currency": "INR",
            "payment_capture": "1"
        })

        # Optionally save cart + form in session for web-based flow
        session["cart"] = data.get("cart", [])
        session["checkout_form"] = data.get("form", {})

        return jsonify({
            "order_id": razorpay_order["id"],
            "amount": amount_in_paise,
            "key_id": "rzp_live_8teFtytXqXhxwa",
            "name": user.get("full_name", ""),
            "email": user.get("email", ""),
            "contact": user.get("phone", "")
        })
    except Exception as e:
        print("❌ Razorpay order creation failed:", e)
        return jsonify({"error": "Payment initialization failed."}), 500

@app.route("/payment_success", methods=["POST"])
def payment_success():
    user = get_user()
    if not user:
        return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401

    data = request.get_json() if request.is_json else request.form
    payment_id = data.get("payment_id") or data.get("razorpay_payment_id")
    cart = data.get("cart") or session.get("cart")
    form = data.get("form") or session.get("checkout_form")

    if not payment_id or not cart or not form:
        return jsonify({"success": False, "error": "Missing payment ID or data"}), 400

    created_at = datetime.now().strftime("%d %b %Y, %I:%M %p")

    try:
        conn = get_orders_db()
        prod_conn = get_products_db()

        for item in cart:
            product_id = item.get("id")
            quantity = int(item.get("qty", 1))
            price = float(item.get("price", 0))
            total = quantity * price
            name = item.get("name", "Unknown Product")

            # Get seller & image
            product = prod_conn.execute("SELECT seller_id, images FROM product WHERE id = ?", (product_id,)).fetchone()
            if not product:
                continue

            # ✅ Parse image
            try:
                raw = product["images"]
                images = json.loads(raw) if raw.strip().startswith("[") else [img.strip() for img in raw.split(",") if img.strip()]
                image = images[0] if images else "default.jpg"
            except:
                image = "default.jpg"

            conn.execute("""
                INSERT INTO orders (
                    item_id, item_name, quantity, amount, status,
                    address1, address2, city, pincode, order_date,
                    user_id, user_name, user_contact, user_email, image,
                    created_at, seller_id, is_paid, payment_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                product_id, name, quantity, total, "accepted",
                form.get("address1", ""), form.get("address2", ""), form.get("city", ""), form.get("zip", ""),
                created_at, user["id"], form.get("full_name", ""), form.get("phone", ""), user.get("email", ""),
                image, created_at, product["seller_id"], 1, payment_id
            ))

        conn.commit()

        # 🧹 Optional: clear saved session (only for web)
        session.pop("cart", None)
        session.pop("checkout_form", None)

        if request.is_json:
            return jsonify({"success": True})
        else:
            flash("✅ Payment successful! Your order has been placed.", "success")
            return redirect(url_for("user_orders"))

    except Exception as e:
        print("⚠️ Order insert failed:", e)
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        conn.close()
        prod_conn.close()
@app.route("/user_settings")
def user_settings():
    user = get_user()

    if not user:
        if "android" in request.headers.get("User-Agent", "").lower():
            return jsonify(success=False, message="Please log in."), 401
        else:
            flash("Please log in", "error")
            return redirect(url_for("user_login"))

    if user.get("role") == "seller":
        if "android" in request.headers.get("User-Agent", "").lower():
            return jsonify(success=False, message="Sellers cannot access user settings."), 403
        else:
            return redirect(url_for("seller_dashboard"))

    if "android" in request.headers.get("User-Agent", "").lower():
        return jsonify({
            "success": True,
            "user": {
                "id": user["id"],
                "name": user.get("full_name", ""),
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "role": user.get("role", "user")
            },
            "settings": {
                "notifications": True,
                "promotions": True,
                "sms": False,
                "personalized": True,
                "usage_sharing": False,
                "remember_payment": True
            }
        })
    else:
        return render_template("user_settings.html", user=user)

@app.route("/deactivate-account", methods=["POST"])
def deactivate_account():
    user = get_user()
    if not user:
        if request.is_json:
            return jsonify(success=False, message="Not logged in.")
        else:
            flash("Login required", "error")
            return redirect(url_for("user_login"))

    if user["role"] in ["admin", "seller", "owner"]:
        msg = "Admins and Owners cannot deactivate."
        if request.is_json:
            return jsonify(success=False, message=msg)
        else:
            flash(msg, "error")
            return redirect(url_for("user_settings"))

    try:
        conn = sqlite3.connect("users.db")
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
        conn.commit()
        conn.close()
        session.clear()

        if request.is_json:
            return jsonify(success=True)
        else:
            flash("Account deactivated.", "success")
            return redirect(url_for("user_home"))

    except Exception as e:
        if request.is_json:
            return jsonify(success=False, message=str(e))
        else:
            flash("Something went wrong.", "error")
            return redirect(url_for("user_settings"))

@app.route("/mobile_settings")
def mobile_settings():
    user = get_user()
    if not user:
        # ⚠️ If mobile, return JSON instead of redirect
        if "android" in request.headers.get("User-Agent", "").lower():
            return jsonify({"success": False, "error": "Login required"}), 401
        else:
            return redirect(url_for("user_login"))

    if "android" in request.headers.get("User-Agent", "").lower():
        return jsonify({
            "success": True,
            "user": {
                "id": user["id"],
                "name": user["full_name"],
                "email": user["email"],
                "role": user["role"]
            },
            "settings": {
                "notifications": True,
                "offers": True,
                "sms": False
            }
        })
    else:
        return render_template("mobile_settings.html", user=user)

@app.route("/user_account", methods=["GET", "POST"])
def user_account():
    user = get_user()
    if not user:
        return redirect(url_for("user_home"))
    
    if user.get("role") == "seller":
        return redirect(url_for("seller_dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        gender_id = request.form.get("gender_id", 1)

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        if 'remove_image' in request.form:
            cur.execute("UPDATE users SET profile_image = NULL WHERE id = ?", (user["id"],))

        image = request.files.get("image")
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            upload_folder = os.path.join(current_app.root_path, "static/images")
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            image.save(filepath)
            image_url = f"/static/images/{filename}"
            cur.execute("UPDATE users SET profile_image = ? WHERE id = ?", (image_url, user["id"]))

        cur.execute("UPDATE users SET full_name = ?, gender_id = ? WHERE id = ?",
                    (full_name, gender_id, user["id"]))
        conn.commit()
        conn.close()

        flash("Account updated successfully.", "success")
        return redirect(url_for("user_account"))

    return render_template("user_account.html", user=user)

@app.route("/change-info", methods=["POST"])
def change_info():
    user = get_user()
    if not user:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("user_account"))

    email = request.form.get("email", "").strip()
    contact = request.form.get("contact", "").strip()

    if not email and not contact:
        flash("Please provide at least one field.", "error")
        return redirect(url_for("user_account"))

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    if email and email != user["email"]:
        if not session.get("otp_verified"):
            flash("Verify OTP before changing email.", "error")
            conn.close()
            return redirect(url_for("user_account"))
        cur.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))

    if contact and contact != user.get("contact"):
        cur.execute("UPDATE users SET contact = ? WHERE id = ?", (contact, user["id"]))

    conn.commit()
    updated_user = cur.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    session["user"] = {
        "email": updated_user["email"],
        "role": updated_user["role"],
        "name": updated_user["full_name"],
        "contact": updated_user["contact"]
    }

    # Clean up OTP session
    for key in ["otp_code", "otp_email", "otp_expiry", "otp_verified", "user_otp_email", "user_otp_code", "user_otp_expiry"]:
        session.pop(key, None)

    conn.close()
    flash("Information updated.", "success")
    return redirect(url_for("user_account"))

@app.route("/send-user-otp", methods=["POST"])
def send_user_otp():
    email = request.json.get("email", "").strip()
    if not email:
        return jsonify(success=False, message="Email is required.")

    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    existing_user = cur.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    user_id = session.get("user_id")

    if user_id:
        current_user = cur.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not current_user:
            conn.close()
            return jsonify(success=False, message="User not found.")

        if email == current_user["email"]:
            conn.close()
            return jsonify(success=False, message="This is already your current email.")

        if existing_user:
            conn.close()
            return jsonify(success=False, message="This email is already in use.")

    otp = generate_random_otp()
    session["user_otp_email"] = email
    session["user_otp_code"] = otp
    session["user_otp_expiry"] = time.time() + 300

    if send_otp_to_email(email, otp):
        return jsonify(success=True, message="OTP sent successfully.")
    else:
        return jsonify(success=False, message="Failed to send OTP.")

@app.route("/verify-user-otp", methods=["POST"])
def verify_user_otp():
    otp = request.json.get("otp", "").strip()
    email = session.get("user_otp_email")
    stored_otp = session.get("user_otp_code")
    expiry = session.get("user_otp_expiry", 0)

    if not otp or not email or not stored_otp:
        return jsonify(verified=False, message="Missing session data.")
    if time.time() > expiry:
        return jsonify(verified=False, message="OTP expired.")
    if otp != stored_otp:
        return jsonify(verified=False, message="Incorrect OTP.")

    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    user_id = session.get("user_id")

    if user_id:
        cur.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        conn.commit()
        session["user"]["email"] = email
        conn.close()
        session["otp_verified"] = True
        return jsonify(verified=True, message="Email updated.")

    user = cur.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user:
        session["user_id"] = user["id"]
        session["user"] = {
            "email": user["email"],
            "role": user["role"],
            "name": user["full_name"],
            "contact": user["contact"]
        }
        conn.close()
        return jsonify(verified=True, message="Logged in.")
    
    conn.close()
    return jsonify(verified=False, message="User not found.")

@app.route("/user_categories")
def user_categories():
    user = get_user()

    if user and user.get("role") in ("seller"):
        return redirect(url_for("seller_dashboard"))
    
    return render_template("user_categories.html")

@app.route("/user_orders")
def user_orders():
    user = get_user()  # Can be None

    email = user["email"] if user else None
    user_orders = []

    if email:
        conn_orders = get_orders_db()
        cursor = conn_orders.execute(
            """
            SELECT id, item_name, quantity, status, address1, address2, city, pincode,
                   created_at, is_paid, amount, image
            FROM orders
            WHERE user_email = ?
            ORDER BY id DESC
            """,
            (email,)
        )
        rows = cursor.fetchall()
        conn_orders.close()

        for row in rows:
            order = dict(row)
            raw_image = order.get("image", "")

            # ✅ Fix: Always set image properly
            try:
                if raw_image.strip().startswith("["):
                    images = json.loads(raw_image)
                else:
                    images = [img.strip() for img in raw_image.split(",") if img.strip()]
                order["image"] = images[0] if images else "default.jpg"
            except Exception as e:
                order["image"] = "default.jpg"

            # ✅ Fix date parsing
            try:
                order["created_at_obj"] = datetime.strptime(order["created_at"], "%d %b %Y, %I:%M %p")
            except (ValueError, TypeError):
                order["created_at_obj"] = order["created_at"]

            user_orders.append(order)

    return render_template(
        "user_orders.html",
        user=user,
        full_name=user.get("full_name", "") if user else "",
        user_orders=user_orders,
        razorpay_key="rzp_live_8teFtytXqXhxwa"
    )

@app.route("/user_order_details/<int:order_id>")
def user_order_details(order_id):
    user = get_user()

    if not user or user.get("role") != "user":
        return redirect(url_for("user_home"))

    user_email = user.get("email")
    user_contact = user.get("contact", "")  # fallback if not stored in orders

    # Fetch order details from orders.db
    conn_orders = get_orders_db()
    conn_orders.row_factory = sqlite3.Row
    cursor = conn_orders.execute(
        """
        SELECT id, item_id, item_name, quantity, amount, status, image,
               address1, address2, city, pincode,
               created_at, accepted_at, cancelled_at, delivered_at,
               user_email, user_contact
        FROM orders
        WHERE id = ? AND user_email = ?
        """,
        (order_id, user_email)
    )
    order = cursor.fetchone()
    conn_orders.close()

    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("user_orders"))

    order = dict(order)

    # Ensure fallback for email/phone if not present
    order['user_email'] = order.get('user_email', user_email)
    order['user_contact'] = order.get('user_contact', user_contact)

    # Fetch product image and ID from products.db
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    product_db_path = os.path.join(BASE_DIR, "products.db")

    if os.path.exists(product_db_path):
        conn_products = sqlite3.connect(product_db_path)
        conn_products.row_factory = sqlite3.Row
        cursor_p = conn_products.execute(
            "SELECT id AS product_id, images FROM product WHERE id = ?",
            (order['item_id'],)
        )
        product = cursor_p.fetchone()
        conn_products.close()

        if product:
            order['product_id'] = product['product_id']
            order['product_image'] = product['images']
        else:
            order['product_id'] = None
            order['product_image'] = None
    else:
        order['product_id'] = None
        order['product_image'] = None
        flash("Product database not found.", "error")

    # Parse dates
    date_format = "%d %b %Y, %I:%M %p"
    for field in ['created_at', 'accepted_at', 'cancelled_at', 'delivered_at']:
        value = order.get(field)
        if value:
            try:
                order[field] = datetime.strptime(value, date_format)
            except:
                order[field] = None

    return render_template(
        "user_order_details.html",
        user=user,
        full_name=user.get("full_name", ""),
        order=order
    )

@app.route('/user_contact', methods=["GET", "POST"])
def user_contact():
    user = get_user()

    if user and user.get("role") in ("seller"):
        return redirect(url_for("seller_dashboard")) 

    if request.method == "POST":
        flash("Messaging system is disabled.", "info")

    return render_template("user_contact.html", full_name=user["full_name"] if user else "", user=user)

@app.route("/ys_about")
def ys_about():
    user = get_user()
    return render_template("ys_about.html", user=user)

@app.route("/ys_shipping")
def ys_shipping():
    user = get_user()
    return render_template("ys_shipping.html", user=user)

@app.route("/ys_terms")
def ys_terms():
    user = get_user()
    return render_template("ys_terms.html", user=user)

@app.route("/ys_refund")
def ys_refund():
    user = get_user()
    return render_template("ys_refund.html", user=user)

@app.route("/ys_faq")
def ys_faq():
    user = get_user()
    return render_template("ys_faq.html", user=user)
      
# seller and owners route ====seller and owners route=======seller and owners route=============seller and owners route=============seller and owners route===================seller and owners route======

@app.route("/seller_login", methods=["GET", "POST"])
def seller_login():
    
    if "user_id" in session:
        return redirect(url_for("seller_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            return redirect(url_for("seller_login"))

        conn = sqlite3.connect("admins.db")
        conn.row_factory = sqlite3.Row
        admins = conn.execute("SELECT * FROM admins WHERE LOWER(email) = ?", (email,)).fetchone()
        conn.close()

        if not admins or not admins["password"]:
            flash("Invalid email or password", "error")
            return redirect(url_for("seller_login"))

        if not check_password_hash(admins["password"], password):
            flash("Invalid email or password", "error")
            return redirect(url_for("seller_login"))

        db_role = admins["role"] if "role" in admins.keys() else "user"
        if db_role not in ("seller", "owner"):
            flash("You are not authorized to log in as Seller.", "error")
            return redirect(url_for("seller_login"))

        session["user_id"] = admins["id"]
        session["user"] = {
            "email": admins["email"],
            "role": db_role,
            "name": admins["full_name"]
        }

        return redirect(url_for("seller_dashboard"))

    return render_template("seller_login.html")

@app.route("/seller_dashboard")
def seller_dashboard():
    user = get_user()
    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    is_seller = user.get("role") == "seller"
    user_id = user.get("id")

    conn = sqlite3.connect("orders.db")
    conn.row_factory = sqlite3.Row

    # Where clause for seller filtering
    where_clause = ""
    params = []

    if is_seller:
        where_clause = "WHERE seller_id = ?"
        params.append(user_id)

    # Total Orders
    total_orders = conn.execute(f"SELECT COUNT(*) FROM orders {where_clause}", params).fetchone()[0]

    # Pending Orders
    pending_orders = conn.execute(f"""
        SELECT COUNT(*) FROM orders {where_clause + (' AND' if where_clause else 'WHERE')} status = 'pending'
    """, params).fetchone()[0]

    # Delivered Orders
    delivered_orders = conn.execute(f"""
        SELECT COUNT(*) FROM orders {where_clause + (' AND' if where_clause else 'WHERE')} status = 'delivered'
    """, params).fetchone()[0]

    # Total Revenue
    total_revenue = conn.execute(f"""
        SELECT SUM(amount) FROM orders {where_clause + (' AND' if where_clause else 'WHERE')} status = 'delivered'
    """, params).fetchone()[0] or 0

    # Revenue trend - last 30 days
    today = datetime.today()
    date_labels = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(29, -1, -1)]
    revenue_map = {d: 0 for d in date_labels}

    revenue_query = f"""
        SELECT order_date, amount FROM orders
        {where_clause + (' AND' if where_clause else 'WHERE')} status = 'delivered'
    """
    results = conn.execute(revenue_query, params).fetchall()
    for row in results:
        order_date = row["order_date"][:10]
        if order_date in revenue_map:
            revenue_map[order_date] += float(row["amount"] or 0)

    chart_labels = list(revenue_map.keys())
    chart_data = [round(revenue_map[d], 2) for d in chart_labels]

    # Top 3 products
    top_query = f"""
        SELECT item_id, item_name, SUM(quantity) AS total_qty, SUM(amount) AS total_sales
        FROM orders
        {where_clause + (' AND' if where_clause else 'WHERE')} status = 'delivered'
        GROUP BY item_id
        ORDER BY total_qty DESC
        LIMIT 3
    """
    top_products_raw = conn.execute(top_query, params).fetchall()
    top_products = [dict(row) for row in top_products_raw]

    conn.close()

    return render_template("seller_dashboard.html",
        user=user,
        full_name=user.get("full_name", "seller"),
        total_orders=total_orders,
        pending_orders=pending_orders,
        delivered_orders=delivered_orders,
        total_revenue=int(total_revenue),
        chart_labels=json.dumps(chart_labels),
        chart_data=json.dumps(chart_data),
        top_products=top_products
    )

@app.route("/seller_orders")
def seller_orders():
    user = get_user()

    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    status_filter = request.args.get("status")
    date_filter = request.args.get("date")

    conn = get_orders_db()
    query = "SELECT * FROM orders WHERE 1=1"
    params = []

    if user.get('role') == 'seller':
        query += " AND seller_id = ?"
        params.append(user.get('id')) 

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    if date_filter:
        query += " AND DATE(order_date) = ?"
        params.append(date_filter)

    query += " ORDER BY order_date DESC"
    cursor = conn.execute(query, params)

    orders = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template(
        "seller_orders.html",
        user=user,
        full_name=user.get("full_name", ""),
        orders=orders,
        selected_status=status_filter or "",
        selected_date=date_filter or ""
    )

@app.route('/edit_order/<int:order_id>', methods=['POST'])
def edit_order(order_id):
    action = request.form.get("action")
    user = get_user()
    if not user or user.get("role") not in ("seller", "owner"):
        flash("Unauthorized", "error")
        return redirect(url_for("seller_orders"))

    conn = get_orders_db()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("seller_orders"))

    # seller can only edit their own orders
    if user["role"] == "seller" and order["seller_id"] != user["id"]:
        flash("You are not authorized to update this order.", "error")
        conn.close()
        return redirect(url_for("seller_orders"))

    if action == "accept" and order["status"] == "pending":
        conn.execute(
            "UPDATE orders SET status = ?, accepted_at = ? WHERE id = ?",
            ("accepted", datetime.now().strftime("%d %b %Y, %I:%M %p"), order_id),
        )
        flash("Order accepted.", "success")

    elif action == "cancel" and order["status"] == "pending":
        conn.execute(
            "UPDATE orders SET status = ?, cancelled_at = ? WHERE id = ?",
            ("cancelled", datetime.now().strftime("%d %b %Y, %I:%M %p"), order_id),
        )
        flash("Order cancelled.", "success")

    elif action == "deliver" and order["status"] == "accepted":
        conn.execute(
            "UPDATE orders SET status = ?, delivered_at = ? WHERE id = ?",
            ("delivered", datetime.now().strftime("%d %b %Y, %I:%M %p"), order_id),
        )
        flash("Order marked as delivered.", "success")

    else:
        flash("Invalid or not allowed action.", "error")

    conn.commit()
    conn.close()
    return redirect(url_for("seller_orders"))

@app.route('/accept_order/<int:order_id>', methods=['POST'])
def accept_order(order_id):
    user = get_user()
    if not user or user.get('role') not in ('seller', 'owner'):
        flash("Unauthorized", "error")
        return redirect(url_for('user_shop'))

    conn = get_orders_db()
    order = conn.execute("SELECT seller_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for('seller_orders'))

    # seller can only accept their own orders
    if user['role'] == 'seller' and order['seller_id'] != user['id']:
        flash("You are not authorized to accept this order.", "error")
        conn.close()
        return redirect(url_for('seller_orders'))

    accepted_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    conn.execute("""
        UPDATE orders
        SET status = 'accepted', accepted_at = ?
        WHERE id = ?
    """, (accepted_at, order_id))
    conn.commit()
    conn.close()

    flash("Order accepted.", "success")
    return redirect(url_for('seller_orders'))

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    user = get_user()
    if not user:
        flash("Unauthorized access.", "error")
        return redirect(url_for("user_home"))

    conn = get_orders_db()
    order = conn.execute("SELECT user_email, status, seller_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("user_shop"))

    is_user = user['email'] == order['user_email']
    is_seller = user.get('role') == 'seller' and order['seller_id'] == user['id']
    is_owner = user.get('role') == 'owner'

    if not (is_user or is_seller or is_owner):
        flash("You are not authorized to cancel this order.", "error")
        conn.close()
        return redirect(url_for("user_shop"))

    if order['status'] != 'pending':
        flash("Only pending orders can be cancelled.", "error")
        conn.close()
        return redirect(url_for("user_orders"))

    cancelled_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    conn.execute("""
        UPDATE orders
        SET status = 'cancelled', cancelled_at = ?
        WHERE id = ?
    """, (cancelled_at, order_id))
    conn.commit()
    conn.close()

    flash("Order cancelled successfully.", "success")
    return redirect(url_for('seller_orders') if user.get('role') in ('seller', 'owner') else url_for('user_orders'))

@app.route('/deliver_order/<int:order_id>', methods=['POST'])
def deliver_order(order_id):
    user = get_user()
    if not user or user.get('role') not in ('seller', 'owner'):
        flash("Unauthorized access.", "error")
        return redirect(url_for("user_shop"))

    conn = get_orders_db()
    order = conn.execute("SELECT status, seller_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("seller_orders"))

    if user['role'] == 'seller' and order['seller_id'] != user['id']:
        flash("You are not authorized to deliver this order.", "error")
        conn.close()
        return redirect(url_for("seller_orders"))

    if order['status'] == 'accepted':
        delivered_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
        conn.execute("""
            UPDATE orders
            SET status = 'delivered', delivered_at = ?
            WHERE id = ?
        """, (delivered_at, order_id))
        conn.commit()
        flash("Order marked as delivered.", "success")
    else:
        flash("Only accepted orders can be marked as delivered.", "error")

    conn.close()
    return redirect(url_for("seller_orders"))

@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    user = get_user()
    if not user or user.get('role') != 'owner':  # ✅ Only owner
        flash("Unauthorized", "error")
        return redirect(url_for('user_shop'))

    conn = get_orders_db()
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    flash("Order deleted.", "success")
    return redirect(url_for('seller_orders'))

@app.route("/seller_catalogs", methods=["GET", "POST"])
def seller_catalogs():
    user = get_user()

    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    full_name = user.get("full_name", "Guest")
    is_owner = user.get("role") == "owner"

    if request.method == "POST":
        name = request.form["name"]
        description = request.form.get("description", "")
        price = request.form["price"]
        discount_price = request.form["discount_price"]
        image_files = request.files.getlist("images")

        if not image_files or image_files[0].filename == "":
            flash("Please upload at least one image.", "error")
            return redirect(url_for("seller_catalogs"))

        upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
        os.makedirs(upload_folder, exist_ok=True)

        filenames = []
        for image in image_files:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(upload_folder, filename))
                filenames.append(filename)
            else:
                flash("All uploaded files must be valid images.", "error")
                return redirect(url_for("seller_catalogs"))

        conn = get_products_db()
        conn.execute(
            "INSERT INTO product (name, description, price, discount_price, images, seller_id) VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, price, discount_price, json.dumps(filenames), user["id"])
        )
        conn.commit()
        conn.close()

        flash("Catalog added successfully!", "success")
        return redirect(url_for("seller_catalogs"))

    # GET
    conn = get_products_db()
    if is_owner:
        rows = conn.execute("SELECT * FROM product ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM product WHERE seller_id = ? ORDER BY id DESC", (user["id"],)).fetchall()

    product_items = []
    for row in rows:
        product_items.append({
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "price": row["price"],
            "discount_price": row["discount_price"],
            "images": json.loads(row["images"]) if row["images"].strip().startswith("[") else [row["images"]]
        })

    conn.close()
    return render_template("seller_catalogs.html", product_items=product_items, full_name=full_name, user=user)


@app.route("/edit_catalog/<int:item_id>", methods=["POST"])
def edit_catalog(item_id):
    user = get_user()
    if not user or user["role"] not in ["seller", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("seller_catalogs"))

    conn = get_products_db()
    product = conn.execute("SELECT images, seller_id FROM product WHERE id = ?", (item_id,)).fetchone()
    if not product:
        flash("Catalog not found", "error")
        return redirect(url_for("seller_catalogs"))

    if user["role"] == "seller" and product["seller_id"] != user["id"]:
        flash("Not allowed to edit this product", "error")
        return redirect(url_for("seller_catalogs"))

    name = request.form["name"]
    description = request.form.get("description", "")
    price = request.form["price"]
    discount_price = request.form["discount_price"]
    image_files = request.files.getlist("images")

    old_images = json.loads(product["images"]) if product["images"].strip().startswith("[") else [product["images"]]
    upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
    new_filenames = old_images

    if image_files and image_files[0].filename != "":
        # Delete old images
        for img in old_images:
            try:
                os.remove(os.path.join(upload_folder, img))
            except:
                pass

        new_filenames = []
        for image in image_files:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(upload_folder, filename))
                new_filenames.append(filename)
            else:
                flash("All uploaded files must be valid images.", "error")
                return redirect(url_for("seller_catalogs"))

    conn.execute("""
        UPDATE product SET name=?, description=?, price=?, discount_price=?, images=?
        WHERE id = ?
    """, (name, description, price, discount_price, json.dumps(new_filenames), item_id))
    conn.commit()
    conn.close()

    flash("Catalog updated", "success")
    return redirect(url_for("seller_catalogs"))

@app.route("/delete_catalog/<int:item_id>", methods=["POST"])
def delete_catalog(item_id):
    user = get_user()
    if not user or user["role"] not in ["seller", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("seller_catalogs"))

    conn = get_products_db()
    row = conn.execute("SELECT images, seller_id FROM product WHERE id = ?", (item_id,)).fetchone()
    if not row:
        flash("Catalog not found", "error")
        return redirect(url_for("seller_catalogs"))

    if user["role"] == "seller" and row["seller_id"] != user["id"]:
        flash("Not allowed to delete", "error")
        return redirect(url_for("seller_catalogs"))

    images_path = os.path.join(current_app.root_path, "static/uploads/products", row["images"])
    if os.path.exists(images_path):
        try:
            os.remove(images_path)
        except:
            pass

    conn.execute("DELETE FROM product WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    flash("Catalog deleted", "success")
    return redirect(url_for("seller_catalogs"))

@app.route("/seller_contact", methods=["GET", "POST"])
def seller_contact():
    user = get_user()  # Get current user for UI display, optional but good
    
    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))
    
    if request.method == "POST":
        # Collect form inputs
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        # Validate input
        if not name or not email or not subject or not message:
            flash("All fields are required.", "error")
            return redirect(url_for("seller_contact"))

        # Compose email to seller
        seller_subject = f"[Contact Form] {subject}"
        seller_body = f"""You received a message from your website contact form:

🧑 Name: {name}
📧 Email: {email}
📝 Subject: {subject}
💬 Message:
{message}
"""

        # Compose thank-you email to user
        user_subject = "Thank you for contacting Yash Cyber Cafe"
        user_body = f"""Hi {name},

Thank you for reaching out to Yash Cyber Cafe. We have received your message and will respond as soon as possible.

🙋 Subject: {subject}
📩 Message: {message}

Best regards,  
Yash Cyber Cafe Team
"""

        # Send both emails
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                # Email to seller
                server.sendmail(
                    EMAIL_ADDRESS,
                    EMAIL_ADDRESS,
                    f"Subject: {seller_subject}\n\n{seller_body}"
                )

                # Thank-you email to user
                server.sendmail(
                    EMAIL_ADDRESS,
                    email,
                    f"Subject: {user_subject}\n\n{user_body}"
                )

            flash("✅ Your message has been sent successfully!", "success")

        except Exception as e:
            print("Email sending error:", e)
            flash("❌ Failed to send your message. Try again later.", "error")

        return redirect(url_for("seller_contact"))

    return render_template("seller_contact.html", user=user)

@app.route("/seller_create", methods=["GET", "POST"])
def seller_create():
    user = get_user()

    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    conn = get_admins_db()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        contact = request.form.get("contact", "").strip()
        address = request.form.get("address", "").strip()

        if not full_name or not email or not contact or not address:
            flash("All fields are required.", "seller_error")
            conn.close()
            return redirect(url_for("seller_create"))

        # ✅ Correct OTP key used here:
        if not session.get("seller_otp_verified_create"):
            flash("OTP verification is required before submission.", "seller_error")
            conn.close()
            return redirect(url_for("seller_create"))

        existing_user = conn.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
        if existing_user:
            flash("Email already exists.", "seller_error")
            conn.close()
            return redirect(url_for("seller_create"))

        default_password = "1234"
        password_hash = generate_password_hash(default_password)

        try:
            conn.execute(
                "INSERT INTO admins (full_name, email, contact, address, password, role) VALUES (?, ?, ?, ?, ?, ?)",
                (full_name, email, contact, address, password_hash, "seller")
            )
            conn.commit()

            # ✅ Send welcome email
            subject = "Your seller Account Credentials"
            body = f"""Hi {full_name},

Your seller account has been created successfully.

📧 Email: {email}
🔐 Default Password: {default_password}
🏠 Address: {address}

Please log in and change your password immediately from your account settings.

Best regards,  
Yash Cyber Cafe Team
"""
            message = f"Subject: {subject}\n\n{body}"

            import smtplib, ssl
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.sendmail(EMAIL_ADDRESS, email, message)

            flash("✅ seller user created and email sent with default credentials.", "seller_success")

            # ✅ Clear session OTP
            session.pop("seller_create_otp", None)
            session.pop("seller_create_email", None)
            session.pop("seller_otp_verified_create", None)
            session.pop("seller_otp_expiry_create", None)

        except Exception as e:
            print("seller creation or email error:", e)
            flash("seller created, but email sending failed.", "seller_error")

    # ✅ Always render list of admins
    admins = conn.execute(
        "SELECT id, full_name, email, contact FROM admins WHERE role = 'seller'"
    ).fetchall()
    conn.close()

    return render_template("seller_create.html", user=user, admins=admins)

@app.route('/delete_seller/<int:seller_id>', methods=['POST'])
def delete_seller(seller_id):
    user = get_user()
    if not user or user.get('role') not in ['seller', 'owner']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('user_home'))

    conn = get_admins_db()
    conn.execute("DELETE FROM admins WHERE id = ? AND role = 'seller'", (seller_id,))
    conn.commit()
    conn.close()

    flash("seller deleted successfully.", "success")
    return redirect(url_for('seller_create'))

@app.route("/seller_settings", methods=["GET", "POST"])
def seller_settings():
    user = get_user()

    if not user:
        return redirect(url_for("seller_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()

        if full_name:
            conn = sqlite3.connect("admins.db")
            cur = conn.cursor()
            cur.execute("UPDATE admins SET full_name = ? WHERE id = ?", (full_name, user["id"]))
            conn.commit()
            conn.close()

            # Update session user if needed
            session["user"]["full_name"] = full_name
            flash("Name updated successfully.", "success")
        else:
            flash("Name cannot be empty.", "error")

        return redirect(url_for("seller_settings"))

    return render_template("seller_settings.html", user=user)

@app.route("/change-sellerinfo", methods=["POST"])
def change_sellerinfo():
    user = get_user()
    if not user:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("seller_login"))

    user_id = user.get("id")
    role = user.get("role")
    if role == "user":
        return redirect(url_for("user_home"))

    new_email = request.form.get("email", "").strip()
    otp = request.form.get("otp", "").strip()
    new_contact = request.form.get("contact", "").strip()

    conn = sqlite3.connect("admins.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    changes_made = False

    # ✅ Email update (requires OTP)
    if new_email and new_email != user["email"]:
        expected_otp = session.get("seller_otp_change")
        verified_flag = session.get("seller_otp_verified_change")

        if not expected_otp or not verified_flag or otp != expected_otp:
            conn.close()
            flash("❌ Invalid or missing OTP for email change.", "error")
            return redirect(url_for("seller_settings"))

        cursor.execute("UPDATE admins SET email = ? WHERE id = ?", (new_email, user_id))
        changes_made = True
        flash("✅ Email updated successfully.", "success")

        # Clean up session OTP
        session.pop("seller_otp_change", None)
        session.pop("seller_otp_email_change", None)
        session.pop("seller_otp_expiry_change", None)
        session.pop("seller_otp_verified_change", None)

    # ✅ Contact update (no OTP required)
    if new_contact and new_contact != user.get("contact"):
        cursor.execute("UPDATE admins SET contact = ? WHERE id = ?", (new_contact, user_id))
        changes_made = True
        flash("📞 Mobile number updated successfully.", "success")

    if changes_made:
        conn.commit()

        # ✅ Refresh session data with updated values
        updated = cursor.execute("SELECT * FROM admins WHERE id = ?", (user_id,)).fetchone()
        session["user"] = {
            "id": updated["id"],
            "email": updated["email"],
            "full_name": updated["full_name"],
            "contact": updated["contact"],
            "role": updated["role"]
        }

    else:
        flash("⚠️ No changes were made.", "warning")

    conn.close()
    return redirect(url_for("seller_settings"))

@app.route("/change-password", methods=["POST"])
def change_password():
    user = get_user()
    if not user:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("seller_settings"))

    old_pw = request.form.get("old_password", "").strip()
    new_pw = request.form.get("new_password", "").strip()
    confirm_pw = request.form.get("confirm_password", "").strip()

    if not old_pw or not new_pw or not confirm_pw:
        flash("All fields are required.", "error")
        return redirect(url_for("seller_settings"))

    if new_pw != confirm_pw:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("seller_settings"))

    conn = sqlite3.connect("admins.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    row = cur.execute("SELECT password FROM admins WHERE email = ?", (user["email"],)).fetchone()
    if not row:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("seller_settings"))

    db_password = row["password"]

    if not check_password_hash(db_password, old_pw):
        conn.close()
        flash("Current password is incorrect.", "error")
        return redirect(url_for("seller_settings"))

    # Update to new password
    new_hashed = generate_password_hash(new_pw)
    cur.execute("UPDATE admins SET password = ? WHERE email = ?", (new_hashed, user["email"]))
    conn.commit()
    conn.close()

    flash("Password updated successfully.", "success")
    return redirect(url_for("seller_settings"))

@app.route("/send-otp", methods=["POST"])
def send_seller_otp():
    data = request.json or {}
    email = data.get("email", "").strip()
    mode = data.get("mode", "create")  # 'create' or 'change'

    if not email:
        return jsonify(success=False, message="Email is required.")

    now = time.time()
    expiry_key = "seller_otp_expiry_" + mode
    otp_key = "seller_otp_" + mode
    email_key = "seller_otp_email_" + mode
    verified_key = "seller_otp_verified_" + mode

    # Check if email exists in admins.db
    conn = sqlite3.connect("admins.db")
    conn.row_factory = sqlite3.Row

    existing = conn.execute("SELECT id FROM admins WHERE email = ?", (email,)).fetchone()

    if mode == "create" and existing:
        conn.close()
        return jsonify(success=False, message="⚠️ Email already exists. Choose another.")

    if mode == "change":
        user = get_user()
        if not user:
            conn.close()
            return jsonify(success=False, message="Session expired.")
        if email == user["email"]:
            conn.close()
            return jsonify(success=False, message="This is already your current email.")
        if existing:
            conn.close()
            return jsonify(success=False, message="Email already in use.")

    conn.close()

    if session.get(expiry_key, 0) > now:
        remaining = int((session[expiry_key] - now) // 60)
        return jsonify(success=False, message=f"OTP already sent. Try again after {remaining} min.")

    otp = generate_random_otp()
    session[otp_key] = otp
    session[email_key] = email
    session[expiry_key] = now + 300
    session[verified_key] = False

    if send_otp_to_email(email, otp):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message="❌ Failed to send OTP.")

@app.route("/verify-otp", methods=["POST"])
def verify_seller_otp():
    data = request.json or {}
    user_otp = data.get("otp", "").strip()
    mode = data.get("mode", "create")  # 'create' or 'change'

    otp_key = "seller_otp_" + mode
    expiry_key = "seller_otp_expiry_" + mode
    verified_key = "seller_otp_verified_" + mode

    actual_otp = session.get(otp_key, "")
    expiry = session.get(expiry_key, 0)

    if time.time() > expiry:
        return jsonify(verified=False, message="OTP expired. Please request a new one.")

    if user_otp == actual_otp:
        session[verified_key] = True
        return jsonify(verified=True)

    return jsonify(verified=False, message="Incorrect OTP.")

# admin ====admin=======admin=============admin=============admin===================admin=============admin================admin=================admin=

@app.route("/admin_create", methods=["GET", "POST"])
def admin_create():
    user = get_user()

    if not user:
        return redirect(url_for("admin_login"))

    if user.get("role") == "user":
        return redirect(url_for("user_home"))

    conn = get_admins_db()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        contact = request.form.get("contact", "").strip()
        address = request.form.get("address", "").strip()

        if not full_name or not email or not contact or not address:
            flash("All fields are required.", "admin_error")
            conn.close()
            return redirect(url_for("admin_create"))

        # ✅ Correct OTP key used here:
        if not session.get("admin_otp_verified_create"):
            flash("OTP verification is required before submission.", "admin_error")
            conn.close()
            return redirect(url_for("admin_create"))

        existing_user = conn.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
        if existing_user:
            flash("Email already exists.", "admin_error")
            conn.close()
            return redirect(url_for("admin_create"))

        default_password = "1234"
        password_hash = generate_password_hash(default_password)

        try:
            conn.execute(
                "INSERT INTO admins (full_name, email, contact, address, password, role) VALUES (?, ?, ?, ?, ?, ?)",
                (full_name, email, contact, address, password_hash, "admin")
            )
            conn.commit()

            # ✅ Send welcome email
            subject = "Your admin Account Credentials"
            body = f"""Hi {full_name},

Your admin account has been created successfully.

📧 Email: {email}
🔐 Default Password: {default_password}
🏠 Address: {address}

Please log in and change your password immediately from your account settings.

Best regards,  
Yash Cyber Cafe Team
"""
            message = f"Subject: {subject}\n\n{body}"

            import smtplib, ssl
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.sendmail(EMAIL_ADDRESS, email, message)

            flash("✅ admin user created and email sent with default credentials.", "admin_success")

            # ✅ Clear session OTP
            session.pop("admin_create_otp", None)
            session.pop("admin_create_email", None)
            session.pop("admin_otp_verified_create", None)
            session.pop("admin_otp_expiry_create", None)

        except Exception as e:
            print("admin creation or email error:", e)
            flash("admin created, but email sending failed.", "admin_error")

    # ✅ Always render list of admins
    admins = conn.execute(
        "SELECT id, full_name, email, contact FROM admins WHERE role = 'admin'"
    ).fetchall()
    conn.close()

    return render_template("admin_create.html", user=user, admins=admins)

@app.route('/delete_admin/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    user = get_user()
    if not user or user.get('role') not in ['admin', 'owner']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('user_home'))

    conn = get_admins_db()
    conn.execute("DELETE FROM admins WHERE id = ? AND role = 'admin'", (admin_id,))
    conn.commit()
    conn.close()

    flash("admin deleted successfully.", "success")
    return redirect(url_for('admin_create'))

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    # ✅ Redirect only if already logged in as admin/owner
    user = session.get("user")
    if user and user.get("role") in ("admin", "owner"):
        return redirect(url_for("admin_lookup"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Please enter both email and password.", "error")
            return redirect(url_for("admin_login"))

        conn = sqlite3.connect("admins.db")
        conn.row_factory = sqlite3.Row
        admin = conn.execute("SELECT * FROM admins WHERE LOWER(email) = ?", (email,)).fetchone()
        conn.close()

        if not admin:
            flash("❌ Invalid email or password.", "error")
            return redirect(url_for("admin_login"))

        if not check_password_hash(admin["password"], password):
            flash("❌ Invalid email or password.", "error")
            return redirect(url_for("admin_login"))

        role = admin["role"] if "role" in admin.keys() else "user"
        if role not in ("admin", "owner"):
            flash("❌ You are not authorized to log in as Admin.", "error")
            return redirect(url_for("admin_login"))

        session["user_id"] = admin["id"]
        session["user"] = {
            "email": admin["email"],
            "role": role,
            "full_name": admin["full_name"]
        }

        return redirect(url_for("admin_lookup"))

    return render_template("admin_login.html")

@app.route("/admin_lookup")
def admin_lookup():
    user = get_user()
    if not user or user.get("role") not in ("admin", "owner"):
        return redirect(url_for("admin_login"))
    return render_template("admin_lookup.html", user=user)


@app.route("/api/seller/<int:id>")
def api_seller(id):
    try:
        conn = sqlite3.connect("admins.db")
        conn.row_factory = sqlite3.Row
        seller = conn.execute(
            "SELECT id, full_name, email, contact, address FROM admins WHERE id = ? AND role = 'seller'", 
            (id,)
        ).fetchone()
        conn.close()

        if not seller:
            return jsonify({"success": False, "message": "Seller not found"})

        return jsonify({"success": True, "details": dict(seller)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/product/<int:id>")
def api_product(id):
    try:
        conn = sqlite3.connect("products.db")
        conn.row_factory = sqlite3.Row
        product = conn.execute(
            "SELECT id, name, price, discount_price, seller_id FROM product WHERE id = ?", 
            (id,)
        ).fetchone()
        conn.close()

        if not product:
            return jsonify({"success": False, "message": "Product not found"})

        return jsonify({"success": True, "details": dict(product)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/order/<int:id>")
def api_order(id):
    try:
        conn = sqlite3.connect("orders.db")
        conn.row_factory = sqlite3.Row
        order = conn.execute("SELECT * FROM orders WHERE id = ?", (id,)).fetchone()
        conn.close()

        if not order:
            return jsonify({"success": False, "message": "Order not found"})

        return jsonify({"success": True, "details": dict(order)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/user/<int:id>")
def api_user(id):
    try:
        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT id, full_name, email, contact FROM users WHERE id = ?", 
            (id,)
        ).fetchone()
        conn.close()

        if not user:
            return jsonify({"success": False, "message": "User not found"})

        return jsonify({"success": True, "details": dict(user)})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

def impersonate_seller(seller_id):
    conn = sqlite3.connect("admins.db")
    conn.row_factory = sqlite3.Row
    seller = conn.execute("SELECT * FROM admins WHERE id = ? AND role = 'seller'", (seller_id,)).fetchone()
    conn.close()
    return seller

@app.route("/admin/seller-panel/<int:id>/dashboard")
def admin_seller_dashboard(id):
    seller = impersonate_seller(id)
    if not seller:
        flash("Seller not found", "error")
        return redirect(url_for("admin_lookup"))

    # Set session to impersonate
    session["user_id"] = seller["id"]
    session["user"] = {
        "email": seller["email"],
        "role": "seller",
        "full_name": seller["full_name"]
    }
    return redirect(url_for("seller_dashboard"))


@app.route("/admin/seller-panel/<int:id>/orders")
def admin_seller_orders(id):
    seller = impersonate_seller(id)
    if not seller:
        flash("Seller not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = seller["id"]
    session["user"] = {
        "email": seller["email"],
        "role": "seller",
        "full_name": seller["full_name"]
    }
    return redirect(url_for("seller_orders"))


@app.route("/admin/seller-panel/<int:id>/products")
def admin_seller_products(id):
    seller = impersonate_seller(id)
    if not seller:
        flash("Seller not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = seller["id"]
    session["user"] = {
        "email": seller["email"],
        "role": "seller",
        "full_name": seller["full_name"]
    }
    return redirect(url_for("seller_products"))


@app.route("/admin/seller-panel/<int:id>/contact")
def admin_seller_contact(id):
    seller = impersonate_seller(id)
    if not seller:
        flash("Seller not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = seller["id"]
    session["user"] = {
        "email": seller["email"],
        "role": "seller",
        "full_name": seller["full_name"]
    }
    return redirect(url_for("seller_contact"))


@app.route("/admin/seller-panel/<int:id>/settings")
def admin_seller_settings(id):
    seller = impersonate_seller(id)
    if not seller:
        flash("Seller not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = seller["id"]
    session["user"] = {
        "email": seller["email"],
        "role": "seller",
        "full_name": seller["full_name"]
    }
    return redirect(url_for("seller_settings"))

def impersonate_user(user_id):
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

@app.route("/admin/user-panel/<int:id>/home")
def admin_user_home(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("user_home"))


@app.route("/admin/user-panel/<int:id>/shop")
def admin_user_shop(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("shop"))  # or use the appropriate route if named differently


@app.route("/admin/user-panel/<int:id>/categories")
def admin_user_categories(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("categories"))


@app.route("/admin/user-panel/<int:id>/orders")
def admin_user_orders(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("my_orders"))


@app.route("/admin/user-panel/<int:id>/profile")
def admin_user_profile(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("account"))


@app.route("/admin/user-panel/<int:id>/cart")
def admin_user_cart(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("cart"))


@app.route("/admin/user-panel/<int:id>/settings")
def admin_user_settings(id):
    user = impersonate_user(id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_lookup"))

    session["user_id"] = user["id"]
    session["user"] = {
        "email": user["email"],
        "role": "user",
        "full_name": user["full_name"]
    }
    return redirect(url_for("setting"))

# misclaneous ====misclaneous=======misclaneous=============misclaneous=============misclaneous===================misclaneous=============misclaneous================misclaneous=================misclaneous=
    
@app.route('/view')
def view_all():
    data = {
        'users': fetch_all('users.db', 'users'),
        'orders': fetch_all('orders.db', 'orders'),
        'products': fetch_all('products.db', 'product'),
        'admins': fetch_all('admins.db', 'admins'),
        'cart': fetch_all('cart.db', 'cart'),
    }
    return render_template('view.html', data=data)

@app.route("/logout")
def logout():
    user = session.get("user")
    role = user.get("role") if user else None

    session.pop("user", None)
    session.pop("user_id", None)

    # Redirect for seller/owner
    if role in ("seller", "owner"):
        return redirect(url_for("seller_login"))
    if role in ("admin"):
        return redirect(url_for("admin_login"))

    # Detect if mobile user
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

    if is_mobile:
        return redirect("/user_shop")
    else:
        return redirect(url_for("user_home"))

@app.route("/my_orders")
def my_orders():
    user = get_user()

    conn_orders = get_orders_db()
    cursor = conn_orders.execute(
        """
        SELECT id, item_name, quantity, status, address1, address2, city, pincode,
               created_at, is_paid, amount, image
        FROM orders
        WHERE user_email = ?
        ORDER BY id DESC
        """,
        (user['email'],)
    )

    rows = cursor.fetchall()
    conn_orders.close()

    my_orders = []
    for row in rows:
        order = dict(row)
        try:
            # Optional: parse datetime
            order["created_at_obj"] = datetime.strptime(order["created_at"], "%d %b %Y, %I:%M %p")
        except (ValueError, TypeError):
            order["created_at_obj"] = order["created_at"]
        my_orders.append(order)

    return render_template(
        "my_orders.html",
        user=user,
        full_name=user.get("full_name", ""),
        my_orders=my_orders,
        razorpay_key="rzp_live_8teFtytXqXhxwa"
    )

if __name__ == "__main__":
    app.run(debug=True)
