from flask import Flask, render_template, request, g, redirect, session, url_for, flash, jsonify, current_app
import sqlite3, os, json, random, string, smtplib, ssl, time, razorpay
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

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

def send_user_welcome_email(email, name):
    import smtplib, ssl

    subject = f"Welcome to {APP_NAME}!"
    body = f"""Hello {name},

🎉 Welcome to {APP_NAME}!

Your account has been created successfully. You can now log in using the following email:

📧 User ID: {email}

If you have any questions or need help, feel free to reach out to our support team.

We're excited to have you on board!

Warm regards,
{APP_NAME} Team
"""

    message = f"Subject: {subject}\n\n{body}"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, message)
        return True
    except Exception as e:
        print("Failed to send user welcome email:", e)
        return False

def send_admin_welcome_email(email, name, password):
    import smtplib, ssl

    subject = f"{APP_NAME} - Admin Account Created"
    body = f"""Hi {name},

Welcome to {APP_NAME}! Your admin account has been created successfully.

📧 Email: {email}
🔐 Default Password: {password}

👉 Please log in and change your password immediately from your account settings for security.

If you did not request this account, please contact the system owner.

Regards,
{APP_NAME} Team
"""

    # Include 'From' properly in the message
    message = f"From: {APP_NAME} <{EMAIL_ADDRESS}>\nTo: {email}\nSubject: {subject}\n\n{body}"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, message)
        print("✅ Admin welcome email sent.")
        return True
    except Exception as e:
        print("❌ Failed to send admin welcome email:", e)
        return False

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

def get_products_db():
    conn = sqlite3.connect('products.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_services_db():
    conn = sqlite3.connect("services.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_orders_db():
    conn = sqlite3.connect("orders.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_temp_password(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

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
    user = session.get("user")
    if not user or not isinstance(user, dict):
        return None

    user_email = user.get("email")
    if not user_email:
        return None

    conn = get_db()
    row = conn.execute(
        """
        SELECT id, full_name, email, profile_image, role, contact, gender_id,
               security_question, security_answer
        FROM users
        WHERE email = ?
        """, (user_email,)
    ).fetchone()

    if row:
        return dict(row)

    return None

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
        return redirect(url_for("dashboard"))

    flash("Invalid credentials", "error")
    return redirect(request.path)

def get_owner_id():
    conn = get_users_db()
    cursor = conn.execute("SELECT id FROM users WHERE role = 'owner' LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result['id'] if result else None

@app.route('/', methods=['GET', 'POST'])
def login_user():
    if 'user_id' in session:
        return redirect(url_for('home'))  # ✅ Already logged in

    if request.method == 'POST':
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            conn.close()
            flash("Invalid email or password", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        # Validate passwords
        is_correct_password = check_password_hash(user["password"], password)

        temp_pass = user["temp_password"] if "temp_password" in user.keys() else None
        usage = user["temp_password_uses"] if "temp_password_uses" in user.keys() else 0
        is_temp_password = temp_pass == password and usage < 2 if temp_pass else False

        if not is_correct_password and not is_temp_password:
            conn.close()
            flash("Invalid email or password", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        # Prevent admin/owner login via this route
        db_role = user["role"] if "role" in user.keys() else "user"
        if db_role in ("admin", "owner"):
            conn.close()
            flash("Please login from admin panel.", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        # Handle temp password usage
        if is_temp_password:
            usage += 1
            if usage >= 2:
                conn.execute(
                    "UPDATE users SET temp_password = NULL, temp_password_uses = 0 WHERE id = ?",
                    (user["id"],)
                )
            else:
                conn.execute(
                    "UPDATE users SET temp_password_uses = ? WHERE id = ?",
                    (usage, user["id"])
                )
            conn.commit()

        conn.close()

        # Set session
        session.permanent = True
        session["user_id"] = user["id"]
        session["user"] = {
            "email": user["email"],
            "role": db_role,
            "name": user["full_name"] if "full_name" in user.keys() else ""
        }

        if is_temp_password:
            flash("🔐 Temporary password used. Please change your password now.", "login_info")
            return redirect(url_for("account", show_change_password="true"))

        return redirect(url_for("home"))

    # GET request — show login form with product & service data
    owner_id = get_owner_id()

    # Fetch product data listed by owner
    conn = get_products_db()
    conn.row_factory = sqlite3.Row
    product_items = conn.execute(
        "SELECT * FROM product WHERE admin_id = ?", (owner_id,)
    ).fetchall()
    conn.close()

    parsed_products = []
    for item in product_items:
        product_dict = dict(item)
        try:
            images = json.loads(product_dict.get('images', '[]'))
            product_dict['image_url'] = images[0] if images else None
        except Exception:
            product_dict['image_url'] = None
        parsed_products.append(product_dict)

    # Fetch service data listed by owner
    conn2 = get_services_db()
    conn2.row_factory = sqlite3.Row
    service_items = conn2.execute(
        "SELECT * FROM services WHERE admin_id = ? ORDER BY id DESC", (owner_id,)
    ).fetchall()
    conn2.close()

    services = [dict(row) for row in service_items]

    return render_template('login_user.html', product_items=parsed_products, service_items=services)

@app.route("/mobile", methods=["GET", "POST"])
def mobile_auth():
    # ✅ Auto-redirect if already logged in
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "login":
            # --- Login logic ---
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()

            if not email or not password:
                flash("Email and password are required.", "login_error")
                return redirect("/mobile")

            conn = sqlite3.connect("users.db")
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if not user:
                conn.close()
                flash("Invalid email or password", "login_error")
                return redirect("/mobile")

            is_correct_password = check_password_hash(user["password"], password)
            temp_pass = user["temp_password"] if "temp_password" in user.keys() else None
            usage = user["temp_password_uses"] if "temp_password_uses" in user.keys() else 0
            is_temp_password = temp_pass == password and usage < 2 if temp_pass else False

            if not is_correct_password and not is_temp_password:
                conn.close()
                flash("Invalid email or password", "login_error")
                return redirect("/mobile")

            db_role = user["role"] if "role" in user.keys() else "user"
            if db_role in ("admin", "owner"):
                conn.close()
                flash("Please login from admin panel.", "login_error")
                return redirect("/mobile")

            if is_temp_password:
                usage += 1
                if usage >= 2:
                    conn.execute(
                        "UPDATE users SET temp_password = NULL, temp_password_uses = 0 WHERE id = ?",
                        (user["id"],)
                    )
                else:
                    conn.execute(
                        "UPDATE users SET temp_password_uses = ? WHERE id = ?",
                        (usage, user["id"])
                    )
                conn.commit()

            conn.close()

            session["user_id"] = user["id"]
            session["user"] = {
                "email": user["email"],
                "role": db_role,
                "name": user["full_name"] if "full_name" in user.keys() else ""
            }

            if is_temp_password:
                flash("🔐 Temporary password used. Please change your password now.", "login_info")
                return redirect(url_for("account", show_change_password="true"))

            return redirect(url_for("home"))

        elif action == "register":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            contact = request.form.get("contact", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not full_name or not email or not contact or not password or not confirm_password:
                flash("All fields are required.", "register_error")
                return redirect("/mobile?open=register")

            if password != confirm_password:
                flash("Passwords do not match.", "register_error")
                return redirect("/mobile?open=register")

            hashed_password = generate_password_hash(password)

            conn = sqlite3.connect("users.db")
            conn.row_factory = sqlite3.Row
            existing = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if existing:
                flash("Email already registered.", "register_error")
                conn.close()
                return redirect("/mobile?open=register")

            conn.execute(
                "INSERT INTO users (full_name, email, contact, password, role) VALUES (?, ?, ?, ?, ?)",
                (full_name, email, contact, hashed_password, "user")
            )
            conn.commit()
            conn.close()

            flash("Registration successful! Please login.", "register_success")
            return redirect("/mobile?open=login")

    # GET request (and not logged in)
    return render_template("mobile.html")

@app.route("/quick-links")
def quick_links():
    return render_template("quick_links.html")

@app.route("/home")
def home():
    user = get_user()

    conn = get_products_db()

    # Fetch product items
    cursor = conn.execute("SELECT id, name, price, discount_price, images FROM product")
    product_items = []
    for row in cursor.fetchall():
        try:
            images = json.loads(row["images"]) if row["images"] else []
        except Exception:
            images = []

        # Safe discount price conversion
        try:
            discount_price = float(row['discount_price']) if row['discount_price'] not in (None, '', 'None') else 0.0
        except Exception:
            discount_price = 0.0

        product_items.append({
            'id': row['id'],
            'name': row['name'],
            'price': float(row['price']),  # Ensure price is a float
            'discount_price': discount_price,
            'images': images
        })

    conn.close()

    return render_template(
        "home.html",
        user=user,
        full_name=user["full_name"] if user else None,
        product_items=product_items
    )


@app.route('/cart/<int:product_id>')
def cart(product_id):
    conn = get_products_db()
    product = conn.execute('SELECT * FROM product WHERE id = ?', (product_id,)).fetchone()
    conn.close()

    if not product:
        flash("Product not found.", "error")
        return redirect(url_for('home'))

    # Safely load images
    try:
        images = json.loads(product['images']) if product['images'] else []
    except Exception:
        images = []

    # Prepare product data
    product_data = {
        'id': product['id'],
        'name': product['name'],
        'description': product['description'],
        'price': float(product['price']),  # Ensure price is float for calculations
        'discount_price': float(product['discount_price']) if product['discount_price'] not in (None, '', 'None') else None,
        'images': images
    }

    return render_template('cart.html', product=product_data)

@app.route("/my_orders")
def my_orders():
    user = get_user()

    if not user or user.get("role") != "user":
        flash("Please log in to view your orders.", "login_error")

        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

        if is_mobile:
            return redirect("/mobile")
        else:
            return redirect(url_for("login_user", open_login="true"))

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

@app.route("/create_razorpay_order/<int:order_id>")
def create_razorpay_order(order_id):
    conn = get_orders_db()  # ✅ Fix: Use correct DB
    cursor = conn.execute("SELECT amount FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    conn.close()

    if not order:
        return jsonify({"error": "Order not found."}), 404

    amount_paise = int(order["amount"] * 100)

    razorpay_order = client.order.create({
        "amount": amount_paise,
        "currency": "INR",
        "payment_capture": 1
    })

    return jsonify({
        "razorpay_order_id": razorpay_order["id"],
        "amount": amount_paise
    })


@app.route("/payment_success", methods=["POST"])
def payment_success():
    data = request.get_json()
    order_id = data.get("order_id")

    # Get current datetime in required format
    accepted_at = datetime.now().strftime("%d %b %Y, %I:%M %p")

    conn = get_orders_db()
    conn.execute("""
        UPDATE orders
        SET is_paid = 1, status = 'accepted', accepted_at = ?
        WHERE id = ?
    """, (accepted_at, order_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/submit_order/<int:item_id>', methods=['POST'])
def submit_order(item_id):
    user = get_user()
    if not user:
        flash("Login required to submit an order", "login_error")
        return redirect(url_for("login_user", open_login="true"))

    # Get form data safely
    name = request.form.get('name', '').strip()
    contact = request.form.get('contact', '').strip()
    email = request.form.get('email', '').strip()
    address1 = request.form.get('address1', '').strip()
    address2 = request.form.get('address2', '').strip()
    city = request.form.get('city', '').strip()
    pincode = request.form.get('pincode', '').strip()
    quantity = request.form.get('quantity', '1').strip()
    amount = request.form.get('amount', '0').strip()

    try:
        quantity = int(quantity)
        amount = float(amount)
    except ValueError:
        flash("Invalid quantity or amount.", "error")
        return redirect(request.referrer or url_for('home'))

    if quantity <= 0 or amount <= 0:
        flash("Quantity and amount must be greater than zero.", "error")
        return redirect(request.referrer or url_for('home'))

    # Get product info (also fetch admin_id here 👇)
    conn_products = get_products_db()
    item = conn_products.execute(
        "SELECT id, name, images, admin_id FROM product WHERE id = ?", (item_id,)
    ).fetchone()
    conn_products.close()

    if not item:
        flash("Item not found.", "error")
        return redirect(url_for("home"))

    try:
        images = json.loads(item['images']) if item['images'] else []
        image = images[0] if images else 'default.jpg'
    except Exception:
        image = 'default.jpg'

    created_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    user_id = user.get('id')
    admin_id = item['admin_id']  # 👈 fetched from product

    # Save order to database (added admin_id)
    conn_orders = get_orders_db()
    conn_orders.execute("""
        INSERT INTO orders (
            item_id, item_name, quantity, amount, status,
            address1, address2, city, pincode, order_date,
            user_id, user_name, user_contact, user_email, image,
            created_at, admin_id  -- 👈 added here
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        item['id'], item['name'], quantity, amount, 'pending',
        address1, address2, city, pincode, created_at,
        user_id, name, contact, email, image,
        created_at, admin_id  # 👈 added here
    ))
    conn_orders.commit()
    conn_orders.close()

    flash('Order submitted successfully!', 'success')
    return redirect(url_for('my_orders'))

@app.route("/my_orders2/<int:order_id>")
def my_orders2(order_id):
    user = get_user()

    if not user or user.get("role") != "user":
        flash("Please log in to view your orders.", "login_error")
        return redirect(url_for("login_user", open_login="true"))

    # Get order info from orders.db
    conn_orders = get_orders_db()
    conn_orders.row_factory = sqlite3.Row
    cursor = conn_orders.execute(
        """
        SELECT id, item_id, item_name, quantity, amount, status, image,
               address1, address2, city, pincode,
               created_at, accepted_at, cancelled_at, delivered_at
        FROM orders
        WHERE id = ? AND user_email = ?
        """,
        (order_id, user['email'])
    )
    order = cursor.fetchone()
    conn_orders.close()

    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("my_orders"))

    order = dict(order)

    # Connect to products.db and fetch product info using item_id
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    product_db_path = os.path.join(BASE_DIR, "products.db")

    if not os.path.exists(product_db_path):
        flash(f"Product database not found at {product_db_path}", "error")
        order['product_id'] = None
        order['product_image'] = None
    else:
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

    # ✅ Parse date strings using correct format from submit_order()
    date_format = "%d %b %Y, %I:%M %p"  # e.g., 25 Jun 2025, 03:45 PM
    date_fields = ['created_at', 'accepted_at', 'cancelled_at', 'delivered_at']

    for field in date_fields:
        raw_value = order.get(field)
        if raw_value:
            try:
                order[field] = datetime.strptime(raw_value, date_format)
            except Exception:
                order[field] = None

    return render_template(
        "my_orders2.html",
        user=user,
        full_name=user.get("full_name", ""),
        order=order
    )

@app.route("/orders")
def orders():
    user = get_user()
    if not user:
        flash("Please log in to view orders.", "error")
        return redirect(url_for("login_user"))

    status_filter = request.args.get("status")
    date_filter = request.args.get("date")

    conn = get_orders_db()
    query = "SELECT * FROM orders WHERE 1=1"
    params = []

    if user.get('role') == 'admin':
        query += " AND admin_id = ?"
        params.append(user.get('id'))  # Filter orders only by this admin's products

    # Owner sees all orders — no need to filter

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
        "orders.html",
        user=user,
        full_name=user.get("full_name", ""),
        orders=orders,
        selected_status=status_filter or "",
        selected_date=date_filter or ""
    )

@app.route('/accept_order/<int:order_id>', methods=['POST'])
def accept_order(order_id):
    user = get_user()
    if not user or user.get('role') not in ('admin', 'owner'):
        flash("Unauthorized", "error")
        return redirect(url_for('home'))

    conn = get_orders_db()
    order = conn.execute("SELECT admin_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for('orders'))

    # Admin can only accept their own orders
    if user['role'] == 'admin' and order['admin_id'] != user['id']:
        flash("You are not authorized to accept this order.", "error")
        conn.close()
        return redirect(url_for('orders'))

    accepted_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    conn.execute("""
        UPDATE orders
        SET status = 'accepted', accepted_at = ?
        WHERE id = ?
    """, (accepted_at, order_id))
    conn.commit()
    conn.close()

    flash("Order accepted.", "success")
    return redirect(url_for('orders'))

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    user = get_user()
    if not user:
        flash("Unauthorized access.", "error")
        return redirect(url_for("login_user"))

    conn = get_orders_db()
    order = conn.execute("SELECT user_email, status, admin_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("home"))

    is_user = user['email'] == order['user_email']
    is_admin = user.get('role') == 'admin' and order['admin_id'] == user['id']
    is_owner = user.get('role') == 'owner'

    if not (is_user or is_admin or is_owner):
        flash("You are not authorized to cancel this order.", "error")
        conn.close()
        return redirect(url_for("home"))

    if order['status'] != 'pending':
        flash("Only pending orders can be cancelled.", "error")
        conn.close()
        return redirect(url_for("my_orders"))

    cancelled_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    conn.execute("""
        UPDATE orders
        SET status = 'cancelled', cancelled_at = ?
        WHERE id = ?
    """, (cancelled_at, order_id))
    conn.commit()
    conn.close()

    flash("Order cancelled successfully.", "success")
    return redirect(url_for('orders') if user.get('role') in ('admin', 'owner') else url_for('my_orders'))

@app.route('/deliver_order/<int:order_id>', methods=['POST'])
def deliver_order(order_id):
    user = get_user()
    if not user or user.get('role') not in ('admin', 'owner'):
        flash("Unauthorized access.", "error")
        return redirect(url_for("home"))

    conn = get_orders_db()
    order = conn.execute("SELECT status, admin_id FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("orders"))

    if user['role'] == 'admin' and order['admin_id'] != user['id']:
        flash("You are not authorized to deliver this order.", "error")
        conn.close()
        return redirect(url_for("orders"))

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
    return redirect(url_for("orders"))

@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    user = get_user()
    if not user or user.get('role') != 'owner':  # ✅ Only owner
        flash("Unauthorized", "error")
        return redirect(url_for('home'))

    conn = get_orders_db()
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    flash("Order deleted.", "success")
    return redirect(url_for('orders'))

@app.route("/sales", methods=["GET", "POST"])
def sales():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    if request.method == "POST":
        name = request.form.get("name")
        contact = request.form.get("contact")
        address1 = request.form.get("address1")
        address2 = request.form.get("address2")
        city = request.form.get("city")
        pincode = request.form.get("pincode")

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect("bill.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO bills (name, contact, address1, address2, city, pincode, total, created_at, admin_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, contact, address1, address2, city, pincode, 0, created_at, user["id"]))
        bill_id = cur.lastrowid

        items = []
        for key in request.form:
            if key.startswith("product_name_"):
                idx = key.split("_")[-1]
                item_name = request.form.get(key)
                qty = int(request.form.get(f"product_qty_{idx}") or 1)
                if item_name:
                    items.append(("product", item_name, qty))
            if key.startswith("service_name_"):
                idx = key.split("_")[-1]
                item_name = request.form.get(key)
                qty = int(request.form.get(f"service_qty_{idx}") or 1)
                if item_name:
                    items.append(("service", item_name, qty))

        total = 0
        for item_type, item_name, qty in items:
            db_file = "products.db" if item_type == "product" else "services.db"
            table = "product" if item_type == "product" else "services"

            lookup_conn = sqlite3.connect(db_file)
            lookup_conn.row_factory = sqlite3.Row
            row = lookup_conn.execute(f"SELECT price, discount_price FROM {table} WHERE name = ?", (item_name,)).fetchone()
            lookup_conn.close()

            if row:
                price = float(row["discount_price"] or row["price"] or 0)
                total += price * qty
                cur.execute("""
                    INSERT INTO bill_items (bill_id, item_type, item_name, quantity, price)
                    VALUES (?, ?, ?, ?, ?)
                """, (bill_id, item_type, item_name, qty, price))

        cur.execute("UPDATE bills SET total = ? WHERE id = ?", (round(total, 2), bill_id))
        conn.commit()
        conn.close()

        flash("✅ Bill saved successfully!", "success")
        return redirect(url_for("sales"))

    # ===== Online Orders =====
    conn = get_orders_db()
    base_query = "SELECT * FROM orders"
    where_clause = ""
    params = []

    if user["role"] == "admin":
        where_clause = " WHERE admin_id = ?"
        params = [user["id"]]

    orders = conn.execute(base_query + where_clause + " ORDER BY order_date DESC", params).fetchall()

    total_orders = conn.execute(f"SELECT COUNT(*) FROM orders{where_clause}", params).fetchone()[0]

    delivered_orders = conn.execute(
        f"SELECT COUNT(*) FROM orders WHERE status = 'delivered'" + (" AND admin_id = ?" if user["role"] == "admin" else ""),
        params if user["role"] == "admin" else []
    ).fetchone()[0]

    pending_orders = conn.execute(
        f"SELECT COUNT(*) FROM orders WHERE status = 'pending'" + (" AND admin_id = ?" if user["role"] == "admin" else ""),
        params if user["role"] == "admin" else []
    ).fetchone()[0]

    total_revenue = conn.execute(
        f"SELECT SUM(amount) FROM orders WHERE status = 'delivered'" + (" AND admin_id = ?" if user["role"] == "admin" else ""),
        params if user["role"] == "admin" else []
    ).fetchone()[0] or 0
    conn.close()

    # ===== Products =====
    conn_products = get_products_db()
    if user["role"] == "admin":
        products = conn_products.execute("SELECT * FROM product WHERE admin_id = ?", (user["id"],)).fetchall()
    else:
        products = conn_products.execute("SELECT * FROM product").fetchall()
    conn_products.close()

    # ===== Services =====
    conn3 = sqlite3.connect("services.db")
    conn3.row_factory = sqlite3.Row
    if user["role"] == "admin":
        services = conn3.execute("SELECT * FROM services WHERE admin_id = ?", (user["id"],)).fetchall()
    else:
        services = conn3.execute("SELECT * FROM services").fetchall()
    conn3.close()

    # ===== Offline Bills =====
    conn2 = sqlite3.connect("bill.db")
    conn2.row_factory = sqlite3.Row
    if user["role"] == "admin":
        offline_bills = conn2.execute("SELECT * FROM bills WHERE admin_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    else:
        offline_bills = conn2.execute("SELECT * FROM bills ORDER BY created_at DESC").fetchall()

    offline_revenue = sum(b["total"] for b in offline_bills if b["total"])
    conn2.close()

    bills = [{
        "id": b["id"],
        "name": b["name"],
        "contact": b["contact"],
        "total": b["total"],
        "address": f"{b['address1']} {b['address2']} {b['city']} {b['pincode']}",
        "date": b["created_at"]
    } for b in offline_bills]

    grand_revenue = int(total_revenue) + round(offline_revenue or 0, 2)

    return render_template("sales.html",
        user=user,
        full_name=user["full_name"],
        total_orders=total_orders,
        delivered_orders=delivered_orders,
        pending_orders=pending_orders,
        total_revenue=int(total_revenue),
        offline_revenue=round(offline_revenue, 2),
        grand_revenue=round(grand_revenue, 2),
        orders=orders,
        bills=bills,
        products=products,
        services=services
    )

@app.route("/bill/delete/<int:bill_id>", methods=["POST"])
def delete_bill(bill_id):
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    conn = sqlite3.connect("bill.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check permission
    cur.execute("SELECT admin_id FROM bills WHERE id = ?", (bill_id,))
    bill = cur.fetchone()

    if not bill:
        conn.close()
        flash("Bill not found.", "error")
        return redirect(url_for("sales"))

    if user["role"] != "owner" and bill["admin_id"] != user["id"]:
        conn.close()
        flash("You are not authorized to delete this bill.", "error")
        return redirect(url_for("sales"))

    cur.execute("DELETE FROM bill_items WHERE bill_id = ?", (bill_id,))
    cur.execute("DELETE FROM bills WHERE id = ?", (bill_id,))
    conn.commit()
    conn.close()

    flash("Bill deleted successfully.", "success")
    return redirect(url_for("sales"))

@app.route("/bill/print/<int:bill_id>")
def print_bill(bill_id):
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    conn = sqlite3.connect("bill.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM bills WHERE id = ?", (bill_id,))
    bill = cur.fetchone()

    if not bill:
        conn.close()
        flash("Bill not found.", "error")
        return redirect(url_for("sales"))

    # Permission check
    if user["role"] != "owner" and bill["admin_id"] != user["id"]:
        conn.close()
        flash("Unauthorized to view this bill.", "error")
        return redirect(url_for("sales"))

    items_raw = cur.execute("SELECT * FROM bill_items WHERE bill_id = ?", (bill_id,)).fetchall()
    conn.close()

    final_items = []
    for item in items_raw:
        item_name = item["item_name"]
        item_type = item["item_type"]
        quantity = int(item["quantity"])

        db_file = "products.db" if item_type == "product" else "services.db"
        table = "product" if item_type == "product" else "services"

        db = sqlite3.connect(db_file)
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute(f"SELECT price, discount_price FROM {table} WHERE name = ?", (item_name,))
        row = cur.fetchone()
        db.close()

        price = float(row["price"]) if row and row["price"] else 0.0
        discount_price = float(row["discount_price"]) if row and row["discount_price"] else price

        final_items.append({
            "item_type": item_type,
            "item_name": item_name,
            "quantity": quantity,
            "price": price,
            "discount_price": discount_price,
            "total": round(discount_price * quantity, 2)
        })

    return render_template("print_receipt.html", bill=bill, items=final_items, user=user)

@app.route('/product', methods=['GET', 'POST'])
def product():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    full_name = user.get("full_name", "Guest")
    is_owner = user.get("role") == "owner"

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        price = request.form['price']
        discount_price = request.form['discount_price']
        images = request.files.getlist('images')

        if not (1 <= len(images) <= 5):
            flash("Upload between 1 to 5 images.", "error")
            return redirect(url_for('product'))

        upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
        os.makedirs(upload_folder, exist_ok=True)
        saved_filenames = []

        for img in images:
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                img_path = os.path.join(upload_folder, filename)
                img.save(img_path)
                saved_filenames.append(filename)

        conn = get_products_db()
        conn.execute(
            "INSERT INTO product (name, description, price, discount_price, images, admin_id) VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, price, discount_price, json.dumps(saved_filenames), user['id'])
        )
        conn.commit()
        conn.close()

        flash("Product item added successfully!", "success")
        return redirect(url_for('product'))

    # GET: Fetch products based on role
    conn = get_products_db()

    if is_owner:
        rows = conn.execute("SELECT * FROM product ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM product WHERE admin_id = ? ORDER BY id DESC", (user["id"],)).fetchall()

    product_items = []
    for row in rows:
        try:
            images = json.loads(row["images"]) if row["images"] else []
        except Exception:
            images = []

        product_items.append({
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "price": row["price"],
            "discount_price": row["discount_price"],
            "images": images
        })
    conn.close()

    return render_template(
        'product.html',
        user=user,
        full_name=full_name,
        product_items=product_items
    )

@app.route('/edit_product/<int:item_id>', methods=['POST'])
def edit_product(item_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("home"))

    conn = get_products_db()
    conn.row_factory = sqlite3.Row

    cur = conn.execute("SELECT images, admin_id FROM product WHERE id = ?", (item_id,))
    row = cur.fetchone()

    if not row:
        flash("Product not found.", "error")
        conn.close()
        return redirect(url_for("product"))

    # 🛡️ Restrict admins from editing others' products
    if user["role"] == "admin" and row["admin_id"] != user["id"]:
        flash("You are not authorized to edit this product.", "error")
        conn.close()
        return redirect(url_for("product"))

    old_images = []
    try:
        old_images = json.loads(row["images"]) if row["images"] else []
    except Exception:
        old_images = row["images"].split(',')

    # 📝 Form fields
    name = request.form['name']
    description = request.form.get('description', '')
    price = request.form['price']
    discount_price = request.form['discount_price']

    uploaded_files = request.files.getlist('images')
    new_images = []

    upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
    os.makedirs(upload_folder, exist_ok=True)

    if uploaded_files and any(f.filename for f in uploaded_files):
        # Delete old images
        for img in old_images:
            try:
                os.remove(os.path.join(upload_folder, img))
            except Exception as e:
                print(f"Error deleting old image {img}: {e}")

        # Save new images
        for file in uploaded_files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                new_images.append(filename)

        if len(new_images) > 5:
            flash("You can upload a maximum of 5 images.", "error")
            conn.close()
            return redirect(url_for('product'))
    else:
        new_images = old_images  # Keep old images if no new ones uploaded

    # 🔄 Update product
    conn.execute("""
        UPDATE product
        SET name = ?, description = ?, price = ?, discount_price = ?, images = ?
        WHERE id = ?
    """, (name, description, price, discount_price, json.dumps(new_images), item_id))

    conn.commit()
    conn.close()

    flash("Product item updated successfully.", "success")
    return redirect(url_for('product'))

@app.route('/delete_product/<int:item_id>', methods=['POST'])
def delete_product(item_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized action.", "error")
        return redirect(url_for("home"))

    conn = get_products_db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Fetch product details including admin_id
    product = cur.execute("SELECT images, admin_id FROM product WHERE id = ?", (item_id,)).fetchone()
    if not product:
        flash("Product not found.", "error")
        conn.close()
        return redirect(url_for("product"))

    # ✅ Admins can delete only their own products
    if user['role'] == 'admin' and product['admin_id'] != user['id']:
        flash("You are not authorized to delete this product.", "error")
        conn.close()
        return redirect(url_for("product"))

    # Delete associated images
    image_list = []
    try:
        image_list = json.loads(product["images"]) if product["images"] else []
    except Exception:
        image_list = product["images"].split(',')

    upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
    for img_filename in image_list:
        img_filename = img_filename.strip()
        if img_filename:
            img_path = os.path.join(upload_folder, img_filename)
            if os.path.exists(img_path):
                try:
                    os.remove(img_path)
                except Exception as e:
                    print(f"Failed to delete image {img_path}: {e}")

    # Delete the product from DB
    cur.execute("DELETE FROM product WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    flash("Product item deleted successfully.", "success")
    return redirect(url_for('product'))

@app.route("/services", methods=["GET", "POST"])
def services():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    conn = get_services_db()

    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        discount_price = request.form.get("discount_price")
        description = request.form.get("description")

        image_url = None
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "":
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(current_app.root_path, "static/uploads/services")
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                image_url = f"/static/uploads/services/{filename}"

        # Insert with admin_id
        conn.execute(
            "INSERT INTO services (name, price, discount_price, description, image_url, admin_id) VALUES (?, ?, ?, ?, ?, ?)",
            (name, price, discount_price, description, image_url, user["id"])
        )
        conn.commit()
        flash("Service added successfully!", "success")

    # Filter services: owner sees all, admin sees only theirs
    conn.row_factory = sqlite3.Row
    if user["role"] == "owner":
        rows = conn.execute("SELECT * FROM services ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM services WHERE admin_id = ? ORDER BY id DESC", (user["id"],)).fetchall()

    conn.close()

    services = [dict(row) for row in rows]
    for s in services:
        s["id"] = s.get("id", 0)
        s["name"] = s.get("name", "")
        s["price"] = s.get("price", 0)
        s["discount_price"] = s.get("discount_price") or ""
        s["description"] = s.get("description") or ""
        s["image_url"] = s.get("image_url") or ""

    return render_template("services.html", user=user, full_name=user["full_name"], services=services)

@app.route('/edit_service/<int:service_id>', methods=['POST'])
def edit_service(service_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("services"))

    conn = get_services_db()
    conn.row_factory = sqlite3.Row
    service = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()

    # Check ownership if user is admin
    if not service or (user["role"] == "admin" and service["admin_id"] != user["id"]):
        flash("Unauthorized access or service not found.", "error")
        conn.close()
        return redirect(url_for("services"))

    name = request.form.get("name")
    price = request.form.get("price")
    discount_price = request.form.get("discount_price")
    description = request.form.get("description")
    image_url = service["image_url"]

    if "image" in request.files:
        file = request.files["image"]
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(current_app.root_path, "static/uploads/services")
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            image_url = f"/static/uploads/services/{filename}"

    conn.execute("""
        UPDATE services
        SET name = ?, price = ?, discount_price = ?, description = ?, image_url = ?
        WHERE id = ?
    """, (name, price, discount_price, description, image_url, service_id))
    conn.commit()
    conn.close()

    flash("Service updated successfully.", "success")
    return redirect(url_for("services"))

@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("services"))

    conn = get_services_db()
    conn.row_factory = sqlite3.Row
    service = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()

    # Check ownership if admin
    if not service or (user["role"] == "admin" and service["admin_id"] != user["id"]):
        flash("Unauthorized to delete this service.", "error")
        conn.close()
        return redirect(url_for("services"))

    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()

    flash("Service deleted successfully.", "success")
    return redirect(url_for("services"))

@app.route('/contact', methods=["GET", "POST"])
def contact():
    user = get_user()

    if not user:
        flash("Please login to contact support.", "login_error")

        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

        if is_mobile:
            return redirect("/mobile")
        else:
            return redirect(url_for("login_user", open_login="true"))

    if request.method == "POST":
        flash("Messaging system is disabled.", "info")
        # You can add more POST logic here if needed

    return render_template("contact.html", full_name=user["full_name"], user=user)

@app.route("/settings")
def settings():
    user = get_user()

    if not user:
        flash("Please log in to access settings.", "login_error")
        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

        if is_mobile:
            return redirect("/mobile")
        else:
            return redirect(url_for("login_user", open_login="true"))

    conn = sqlite3.connect("security.db")
    conn.row_factory = sqlite3.Row
    questions = conn.execute("SELECT * FROM security_questions").fetchall()
    conn.close()

    return render_template("settings.html", user=user, full_name=user.get("full_name"), questions=questions)

@app.route("/delete-account", methods=["POST"])
def delete_account():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    email = user["email"]
    role = user.get("role", "")

    # Block deletion differently for admin and owner
    if role == "admin":
        flash("Admin users cannot delete their account directly.", "error")
        return redirect(url_for("settings", admin_delete_blocked=1))
    elif role == "owner":
        flash("Owner account deletion is restricted.", "error")
        return redirect(url_for("settings", owner_delete_blocked=1))

    try:
        conn = sqlite3.connect("users.db")
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Delete Error:", e)
        flash("❌ Failed to delete account. Try again.", "error")
        return redirect(url_for("settings"))

    session.pop("user_id", None)
    session.pop("user", None)
    flash("✅ Your account has been deleted.", "success")
    return redirect(url_for("register"))

import os
import sqlite3
from flask import (
    request, redirect, url_for, flash, render_template,
    current_app
)
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/account", methods=["GET", "POST"])
def account():
    user = get_user()
    if not user:
        flash("Please log in to access your account.", "login_error")
        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

        if is_mobile:
            return redirect("/mobile")
        else:
            return redirect(url_for("login_user", open_login="true"))

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
        return redirect(url_for("account"))

    conn = sqlite3.connect("security.db")
    questions = conn.execute("SELECT * FROM questions").fetchall()
    conn.close()

    return render_template("account.html", user=user, questions=questions)

@app.route("/change-password", methods=["POST"])
def change_password():
    user = get_user()
    if not user:
        return redirect(url_for("account"))

    old_pw = request.form.get("old_password")
    new_pw = request.form.get("new_password")
    confirm_pw = request.form.get("confirm_password")

    if new_pw != confirm_pw:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("account"))

    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    row = cur.execute("SELECT password, temp_password, temp_password_uses FROM users WHERE email = ?", (user["email"],)).fetchone()

    if not row:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("account"))

    db_password = row["password"]
    temp_password = row["temp_password"]
    temp_uses = row["temp_password_uses"] or 0

    # Check if old_pw matches real OR valid temp password
    is_real = check_password_hash(db_password, old_pw)
    is_temp = temp_password == old_pw and temp_uses < 2

    if is_real or is_temp:
        cur.execute("""
            UPDATE users
            SET password = ?, temp_password = NULL, temp_password_uses = 0
            WHERE email = ?
        """, (generate_password_hash(new_pw), user["email"]))
        conn.commit()
        flash("Password updated successfully.", "success")
    else:
        flash("Current password is incorrect.", "error")

    conn.close()
    return redirect(url_for("account"))

@app.route("/change-info", methods=["POST"])
def change_info():
    user = get_user()
    if not user:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("account"))

    email = request.form.get("email", "").strip()
    contact = request.form.get("contact", "").strip()

    if not email and not contact:
        flash("Please provide at least one field to update.", "error")
        return redirect(url_for("account"))

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    # ✅ If email is changed, require OTP
    if email and email != user["email"]:
        if not session.get("otp_verified"):
            flash("Please verify OTP before changing your email.", "error")
            conn.close()
            return redirect(url_for("account"))
        cur.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
        session["user"]["email"] = email  # Update session email
        # Clear OTP session after success
        session.pop("otp_verified", None)
        session.pop("register_otp", None)
        session.pop("otp_expiry", None)

    if contact and contact != user["contact"]:
        cur.execute("UPDATE users SET contact = ? WHERE id = ?", (contact, user["id"]))
        session["user"]["contact"] = contact

    conn.commit()
    conn.close()

    flash("Information updated successfully.", "success")
    return redirect(url_for("account"))

@app.route("/set-security", methods=["POST"])
def set_security():
    user_id = session.get("user_id")
    if not user_id:
        user = session.get("user")
        if not user:
            flash("Session expired. Please login again.", "error")
            return redirect(url_for("account"))

        # Get user id from DB if not in session
        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id FROM users WHERE email = ?", (user["email"],)).fetchone()
        conn.close()

        if not row:
            flash("User not found.", "error")
            return redirect(url_for("account"))

        user_id = row["id"]
        session["user_id"] = user_id  # Save it for next time

    question = request.form.get("question")
    answer = request.form.get("answer")

    if not question or not answer:
        flash("Please select a question and provide an answer.", "error")
        return redirect(url_for("account"))

    conn = sqlite3.connect("users.db")
    conn.execute("""
        UPDATE users
        SET security_question = ?, security_answer = ?
        WHERE id = ?
    """, (question, answer, user_id))
    conn.commit()
    conn.close()

    flash("Security question and answer updated successfully.", "success")
    return redirect(url_for("account"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    temp_password = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        contact = request.form.get("contact", "").strip()
        question = request.form.get("question", "").strip()
        answer = request.form.get("answer", "").strip()

        if not (email or contact):
            flash("Please fill at least Email or Mobile Number.", "error")
        elif not question or not answer:
            flash("Security question and answer are required.", "error")
        else:
            conn = sqlite3.connect("users.db")
            conn.row_factory = sqlite3.Row

            user = conn.execute("""
                SELECT * FROM users
                WHERE (email = ? OR contact = ?) AND security_question = ? AND security_answer = ?
            """, (email, contact, question, answer)).fetchone()

            if user:
                # Example temp password logic
                temp_password = "Temp@123"  # or generate randomly
                conn.execute("UPDATE users SET temp_password = ? WHERE id = ?", (temp_password, user["id"]))
                conn.commit()
                flash(f"🔑 Your temporary password is <b>{temp_password}</b>. It can be used only 2 times. Please change your password after login.", "success")
            else:
                flash("User not found or incorrect security answer.", "error")

            conn.close()

    # Fetch questions from security.db
    conn2 = sqlite3.connect("security.db")
    questions = conn2.execute("SELECT * FROM questions").fetchall()
    conn2.close()

    return render_template("forgot.html", questions=questions, temp_password=temp_password)

@app.route("/send-reset-otp", methods=["POST"])
def send_reset_otp():
    email = request.json.get("email", "").strip().lower()

    if not email:
        return jsonify(success=False, message="⚠️ Email is required.")

    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify(success=False, message="❌ This email is not registered.")

    now = time.time()
    otp_expiry = session.get("otp_expiry", 0)

    # Cooldown to prevent OTP spamming
    if otp_expiry and now < otp_expiry:
        remaining = int((otp_expiry - now) // 60) + 1
        return jsonify(success=False, message=f"⚠️ OTP already sent. Try again in {remaining} minute(s).")

    # Generate OTP (example: 6-digit random)
    otp = generate_random_otp()

    # Store in session
    session["register_email"] = email
    session["register_otp"] = otp
    session["otp_expiry"] = now + 300   # 5 minutes
    session["otp_verified"] = False

    # Send OTP
    if send_otp_to_email(email, otp):
        return jsonify(success=True, message="✅ OTP has been sent to your email.")

    return jsonify(success=False, message="❌ Failed to send OTP. Please try again.")

@app.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp = data.get("otp", "").strip()

    # Get stored values from session
    saved_otp = session.get("register_otp")
    saved_email = session.get("register_email")
    expiry = session.get("otp_expiry", 0)

    # Check if OTP is valid
    if not saved_otp or not saved_email or time.time() > expiry:
        return jsonify(success=False, message="❌ OTP expired or not found.")

    if email != saved_email:
        return jsonify(success=False, message="❌ Email does not match.")

    if otp != saved_otp:
        return jsonify(success=False, message="❌ Invalid OTP.")

    session["otp_verified"] = True
    return jsonify(success=True, message="✅ OTP verified successfully.")

@app.route("/recover_otp", methods=["POST"])
def recover_otp():
    email = request.form.get("otp_email", "").strip().lower()
    otp = request.form.get("otp_code", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Check all fields are filled
    if not email or not otp or not new_password or not confirm_password:
        flash("⚠️ All fields are required.", "error")
        return redirect(url_for("forgot"))

    # Check password match
    if new_password != confirm_password:
        flash("❌ Passwords do not match.", "error")
        return redirect(url_for("forgot"))

    # Check user exists
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        conn.close()
        flash("❌ Email does not exist.", "error")
        return redirect(url_for("forgot"))

    # Validate OTP from session
    stored_otp = session.get("register_otp")
    stored_email = session.get("register_email")
    expiry = session.get("otp_expiry", 0)
    is_verified = session.get("otp_verified", False)

    if not stored_otp or not stored_email:
        conn.close()
        flash("❌ No OTP found. Please request again.", "error")
        return redirect(url_for("forgot"))

    if email != stored_email:
        conn.close()
        flash("❌ Email does not match the one used for OTP.", "error")
        return redirect(url_for("forgot"))

    if time.time() > expiry:
        conn.close()
        flash("⌛ OTP has expired. Please request a new one.", "error")
        return redirect(url_for("forgot"))

    if otp != stored_otp:
        conn.close()
        flash("❌ Incorrect OTP. Please try again.", "error")
        return redirect(url_for("forgot"))

    if not is_verified:
        conn.close()
        flash("⚠️ Please verify your OTP before resetting the password.", "error")
        return redirect(url_for("forgot"))

    # Update the password
    hashed_pw = generate_password_hash(new_password)
    try:
        conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email))
        conn.commit()
        flash("✅ Password reset successful. Please login.", "success")
        # Optional: clear OTP session data
        session.pop("register_email", None)
        session.pop("register_otp", None)
        session.pop("otp_verified", None)
        session.pop("otp_expiry", None)
    except Exception as e:
        print("Error resetting password:", e)
        flash("❌ Something went wrong. Please try again.", "error")
    finally:
        conn.close()

    return redirect(url_for("login_user"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        contact = request.form.get("contact", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        otp = request.form.get("otp", "").strip()

        # Validate required fields
        if not full_name or not contact or not email or not password or not confirm_password:
            flash("All fields are required.", "register_error")
            return redirect(url_for("login_user"))

        if password != confirm_password:
            flash("Passwords do not match.", "register_error")
            return redirect(url_for("login_user"))

        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            conn.execute(
                "INSERT INTO users (full_name, contact, email, password, role) VALUES (?, ?, ?, ?, ?)",
                (full_name, contact, email, hashed_pw, 'user')
            )
            conn.commit()

            # ✅ Send welcome email after successful registration
            send_user_welcome_email(email, full_name)

            flash("Registration successful. Please login.", "register_success")

        except sqlite3.IntegrityError:
            flash("Email already registered.", "register_error")
        except Exception as e:
            flash("Something went wrong. Please try again.", "register_error")
            print("Registration error:", str(e))
        finally:
            conn.close()

        return redirect(url_for("login_user"))

    return redirect(url_for("login_user"))

@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email", "").strip()
    if not email:
        return jsonify(success=False, message="Email is required.")

    # ✅ Check if email already exists in users database
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if user:
        return jsonify(success=False, message="⚠️ Email already exists. Please log in instead.")

    # ✅ Cooldown check
    now = time.time()
    expiry = session.get("otp_expiry", 0)
    if expiry and now < expiry:
        remaining = int((expiry - now) // 60)
        return jsonify(success=False, message=f"OTP already sent. Try again after {remaining} min.")

    # ✅ Generate and send OTP
    otp = generate_random_otp()
    session["register_otp"] = otp
    session["register_email"] = email
    session["otp_expiry"] = now + 300  # 5 minutes
    session["otp_verified"] = False

    if send_otp_to_email(email, otp):
        return jsonify(success=True)

    return jsonify(success=False, message="❌ Failed to send OTP. Try again later.")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    user_otp = request.json.get("otp", "").strip()
    actual_otp = session.get("register_otp", "").strip()
    expiry = session.get("otp_expiry", 0)

    if datetime.now().timestamp() > expiry:
        return jsonify(verified=False, message="OTP expired. Please request a new one.")

    if user_otp == actual_otp:
        session["otp_verified"] = True
        return jsonify(verified=True)

    return jsonify(verified=False, message="Incorrect OTP.")

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    user = get_user()
    if not user or user.get('role') not in ['admin', 'owner']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login_user'))

    conn = get_users_db()

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        contact = request.form.get('contact')

        if not full_name or not email or not contact:
            flash("All fields are required.", "error")
            conn.close()
            return redirect(url_for('create_admin'))

        existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing_user:
            flash("Email already exists.", "error")
            conn.close()
            return redirect(url_for('create_admin'))

        default_password = '1234'
        password_hash = generate_password_hash(default_password)

        try:
            conn.execute(
                "INSERT INTO users (full_name, email, contact, password, role) VALUES (?, ?, ?, ?, ?)",
                (full_name, email, contact, password_hash, 'admin')
            )
            conn.commit()

            # Send welcome email with plain password used
            subject = "Your Admin Account Credentials"
            body = f"""Hi {full_name},

Your admin account has been created successfully.

📧 Email: {email}
🔐 Default Password: {default_password}

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

            flash("Admin user created and email sent with default credentials.", "success")
        except Exception as e:
            print("Admin creation or email error:", e)
            flash("Admin created, but email sending failed.", "error")

    admins = conn.execute("SELECT id, full_name as name, email, contact FROM users WHERE role = 'admin'").fetchall()
    conn.close()

    return render_template('create_admin.html', user=user, admins=admins)

@app.route('/delete_admin/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    user = get_user()
    if not user or user.get('role') not in ['admin', 'owner']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login_user'))

    conn = get_users_db()
    conn.execute("DELETE FROM users WHERE id = ? AND role = 'admin'", (admin_id,))
    conn.commit()
    conn.close()

    flash("Admin deleted successfully.", "success")
    return redirect(url_for('create_admin'))

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    # ✅ Auto-redirect if already logged in
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("login_admin"))

        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
        conn.close()

        if not user or not user["password"]:
            flash("Invalid email or password", "error")
            return redirect(url_for("login_admin"))

        if not check_password_hash(user["password"], password):
            flash("Invalid email or password", "error")
            return redirect(url_for("login_admin"))

        db_role = user["role"] if "role" in user.keys() else "user"
        if db_role not in ("admin", "owner"):
            flash("You are not authorized to log in as Admin/Owner.", "error")
            return redirect(url_for("login_admin"))

        session["user_id"] = user["id"]
        session["user"] = {
            "email": user["email"],
            "role": db_role,
            "name": user["full_name"]
        }

        return redirect(url_for("home"))

    return render_template("login_admin.html")

@app.route("/logout")
def logout():
    user = session.get("user")
    role = user.get("role") if user else None

    session.pop("user", None)
    session.pop("user_id", None)

    # Redirect for admin/owner
    if role in ("admin", "owner"):
        return redirect(url_for("login_admin"))

    # Detect if mobile user
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

    if is_mobile:
        return redirect("/mobile")
    else:
        return redirect(url_for("login_user", open_login="true"))

if __name__ == "__main__":
    app.run(debug=True)
