from flask import Flask, render_template, request, g, redirect, session, url_for, flash, jsonify, current_app
import os, json, random, string, smtplib, ssl, time, razorpay, mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

client = razorpay.Client(auth=("rzp_live_8teFtytXqXhxwa", "wv24XQhmouaxsoyPJ2F2hAX4"))

APP_NAME = "Yash Cyber Cafe"
EMAIL_ADDRESS = "yashcybercafeofficial@gmail.com"
EMAIL_PASSWORD = "jgwujcylyefeaefz"
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_mysql_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Yashwant@7987",
        database="cybercafe_app"
    )

def generate_random_otp(length=6):
    return ''.join(random.choices('0123456789', k=length))

def send_otp_to_email(email, otp):
    subject = f"{APP_NAME} - OTP Verification"
    body = f"""Hello,

Your OTP for {APP_NAME} is: {otp}

This code is valid for 5 minutes. Please do not share it with anyone.

Regards,  
{APP_NAME} Team
"""
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
        if isinstance(value, str):
            utc = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        elif isinstance(value, datetime):
            utc = value
        else:
            return value  # Unknown format

        # Convert UTC to IST properly
        ist = utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Asia/Kolkata"))
        return ist.strftime("%d %b %Y, %I:%M %p")
    except Exception as e:
        print("Date format error:", e)
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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, full_name, email, profile_image, role, contact, gender_id,
               security_question, security_answer
        FROM users
        WHERE email = %s
    """, (user_email,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    return row if row else None

def handle_login(expected_role):
    email = request.form.get("email")
    password = request.form.get("password")

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
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
    conn = get_mysql_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE role = 'owner' LIMIT 1")
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None

@app.route("/", methods=["GET", "POST"])
def login_user():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        conn = get_mysql_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            flash("Invalid email or password", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        is_correct_password = check_password_hash(user["password"], password)
        temp_pass = user.get("temp_password")
        usage = user.get("temp_password_uses", 0)
        is_temp_password = temp_pass == password and usage < 2 if temp_pass else False

        if not is_correct_password and not is_temp_password:
            cur.close()
            conn.close()
            flash("Invalid email or password", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        db_role = user.get("role", "user")
        if db_role in ("admin", "owner"):
            cur.close()
            conn.close()
            flash("Please login from admin panel.", "login_error")
            return redirect(url_for("login_user", open_login="true"))

        if is_temp_password:
            usage += 1
            if usage >= 2:
                cur.execute(
                    "UPDATE users SET temp_password = NULL, temp_password_uses = 0 WHERE id = %s",
                    (user["id"],)
                )
            else:
                cur.execute(
                    "UPDATE users SET temp_password_uses = %s WHERE id = %s",
                    (usage, user["id"])
                )
            conn.commit()

        cur.close()
        conn.close()

        session["user_id"] = user["id"]
        session["user"] = {
            "email": user["email"],
            "role": db_role,
            "name": user.get("full_name", "")
        }

        if is_temp_password:
            flash("🔐 Temporary password used. Please change your password now.", "login_info")
            return redirect(url_for("account", show_change_password="true"))

        return redirect(url_for("home"))

    # --- GET Method: Load products and services ---
    owner_id = get_owner_id()
    conn = get_mysql_connection()

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE admin_id = %s", (owner_id,))
    products_items = cursor.fetchall()
    cursor.close()

    parsed_products = []
    for item in products_items:
        try:
            images = json.loads(item.get('images', '[]'))
            item['image_url'] = images[0] if images else None
        except Exception:
            item['image_url'] = None
        parsed_products.append(item)

    cursor2 = conn.cursor(dictionary=True)
    cursor2.execute("SELECT * FROM services WHERE admin_id = %s ORDER BY id DESC", (owner_id,))
    service_items = cursor2.fetchall()
    cursor2.close()
    conn.close()

    return render_template("login_user.html", products_items=parsed_products, service_items=service_items)

@app.route("/mobile", methods=["GET", "POST"])
def mobile_auth():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "login":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()

            if not email or not password:
                flash("Email and password are required.", "login_error")
                return redirect("/mobile")

            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user:
                conn.close()
                flash("Invalid email or password", "login_error")
                return redirect("/mobile")

            is_correct_password = check_password_hash(user["password"], password)
            temp_pass = user.get("temp_password")
            usage = user.get("temp_password_uses", 0)
            is_temp_password = temp_pass == password and usage < 2 if temp_pass else False

            if not is_correct_password and not is_temp_password:
                conn.close()
                flash("Invalid email or password", "login_error")
                return redirect("/mobile")

            db_role = user.get("role", "user")
            if db_role in ("admin", "owner"):
                conn.close()
                flash("Please login from admin panel.", "login_error")
                return redirect("/mobile")

            if is_temp_password:
                usage += 1
                if usage >= 2:
                    cursor.execute("UPDATE users SET temp_password = NULL, temp_password_uses = 0 WHERE id = %s", (user["id"],))
                else:
                    cursor.execute("UPDATE users SET temp_password_uses = %s WHERE id = %s", (usage, user["id"]))
                conn.commit()

            conn.close()

            session["user_id"] = user["id"]
            session["user"] = {
                "email": user["email"],
                "role": db_role,
                "name": user.get("full_name", "")
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

            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing = cursor.fetchone()
            if existing:
                flash("Email already registered.", "register_error")
                conn.close()
                return redirect("/mobile?open=register")

            cursor.execute(
                "INSERT INTO users (full_name, email, contact, password, role) VALUES (%s, %s, %s, %s, %s)",
                (full_name, email, contact, hashed_password, "user")
            )
            conn.commit()
            conn.close()

            flash("Registration successful! Please login.", "register_success")
            return redirect("/mobile?open=login")

    return render_template("mobile.html")

@app.route("/quick-links")
def quick_links():
    return render_template("quick_links.html")

@app.route("/home")
def home():
    user = session.get("user")

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, price, discount_price, images FROM products")
    rows = cursor.fetchall()
    conn.close()

    products_items = []
    for row in rows:
        try:
            images = json.loads(row["images"]) if row["images"] else []
        except Exception:
            images = []

        try:
            discount_price = float(row['discount_price']) if row['discount_price'] not in (None, '', 'None') else 0.0
        except Exception:
            discount_price = 0.0

        products_items.append({
            'id': row['id'],
            'name': row['name'],
            'price': float(row['price']),
            'discount_price': discount_price,
            'images': images
        })

    return render_template("home.html", user=user, full_name=user.get("full_name") if user else None, products_items=products_items)

@app.route('/cart/<int:products_id>')
def cart(products_id):
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM products WHERE id = %s', (products_id,))
    products = cursor.fetchone()
    conn.close()

    if not products:
        flash("products not found.", "error")
        return redirect(url_for('home'))

    try:
        images = json.loads(products['images']) if products['images'] else []
    except Exception:
        images = []

    products_data = {
        'id': products['id'],
        'name': products['name'],
        'description': products['description'],
        'price': float(products['price']),
        'discount_price': float(products['discount_price']) if products['discount_price'] not in (None, '', 'None') else None,
        'images': images
    }

    return render_template('cart.html', products=products_data)

@app.route("/my_orders")
def my_orders():
    user = session.get("user")

    if not user or user.get("role") != "user":
        flash("Please log in to view your orders.", "login_error")
        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent
        if is_mobile:
            return redirect("/mobile")
        else:
            return redirect(url_for("login_user", open_login="true"))

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, item_name, quantity, status, address1, address2, city, pincode, 
               created_at, is_paid, amount, image
        FROM orders 
        WHERE user_email = %s
        ORDER BY id DESC
    """, (user['email'],))
    rows = cursor.fetchall()
    conn.close()

    my_orders = []
    for row in rows:
        try:
            row["created_at_obj"] = datetime.strptime(row["created_at"], "%d %b %Y, %I:%M %p")
        except (ValueError, TypeError):
            row["created_at_obj"] = row["created_at"]
        my_orders.append(row)

    return render_template("my_orders.html", user=user, full_name=user.get("full_name", ""), my_orders=my_orders, razorpay_key="rzp_live_8teFtytXqXhxwa")

@app.route("/my_orders2/<int:order_id>")
def my_orders2(order_id):
    user = get_user()

    if not user or user.get("role") != "user":
        flash("Please log in to view your orders.", "login_error")
        return redirect(url_for("login_user", open_login="true"))

    # ✅ Get order info from MySQL
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, item_id, item_name, quantity, amount, status, image,
               address1, address2, city, pincode,
               created_at, accepted_at, cancelled_at, delivered_at
        FROM orders
        WHERE id = %s AND user_email = %s
        """,
        (order_id, user['email'])
    )
    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found.", "error")
        return redirect(url_for("my_orders"))

    # ✅ Get products info from MySQL (same DB now)
    cursor.execute(
        "SELECT id AS products_id, images FROM products WHERE id = %s",
        (order['item_id'],)
    )
    products = cursor.fetchone()

    order['products_id'] = products['products_id'] if products else None
    order['products_image'] = products['images'] if products else None

    conn.close()

    # ✅ Convert string date fields to datetime objects
    date_format = "%d %b %Y, %I:%M %p"
    date_fields = ['created_at', 'accepted_at', 'cancelled_at', 'delivered_at']

    for field in date_fields:
        raw_value = order.get(field)
        if raw_value and isinstance(raw_value, str):
            try:
                order[field] = datetime.strptime(raw_value, date_format)
            except Exception:
                order[field] = None
        elif isinstance(raw_value, datetime):
            order[field] = raw_value
        else:
            order[field] = None

    return render_template(
        "my_orders2.html",
        user=user,
        full_name=user.get("full_name", ""),
        order=order
    )

@app.route("/create_razorpay_order/<int:order_id>")
def create_razorpay_order(order_id):
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT amount FROM orders WHERE id = %s", (order_id,))
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

    accepted_at = datetime.now().strftime("%d %b %Y, %I:%M %p")

    conn = get_mysql_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE orders 
        SET is_paid = 1, status = 'accepted', accepted_at = %s 
        WHERE id = %s
    """, (accepted_at, order_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/submit_order/<int:item_id>', methods=['POST'])
def submit_order(item_id):
    user = session.get("user")
    if not user:
        flash("Login required to submit an order", "login_error")
        return redirect(url_for("login_user", open_login="true"))

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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, images, admin_id FROM products WHERE id = %s", (item_id,))
    item = cursor.fetchone()
    conn.close()

    if not item:
        flash("Item not found.", "error")
        return redirect(url_for("home"))

    try:
        images = json.loads(item['images']) if item['images'] else []
        image = images[0] if images else 'default.jpg'
    except Exception:
        image = 'default.jpg'

    # ✅ Use MySQL-compatible datetime format
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_id = user.get('id')
    admin_id = item['admin_id']

    conn = get_mysql_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (
            item_id, item_name, quantity, amount, status,
            address1, address2, city, pincode, order_date,
            user_id, user_name, user_contact, user_email, image,
            created_at, admin_id
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        item['id'], item['name'], quantity, amount, 'pending',
        address1, address2, city, pincode, created_at,
        user_id, name, contact, email, image,
        created_at, admin_id
    ))
    conn.commit()
    conn.close()

    flash('Order submitted successfully!', 'success')
    return redirect(url_for('my_orders'))

@app.route("/orders")
def orders():
    user = get_user()
    if not user:
        flash("Please log in to view orders.", "error")
        return redirect(url_for("login_user"))

    status_filter = request.args.get("status")
    date_filter = request.args.get("date")  # format: YYYY-MM-DD

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT * FROM orders WHERE 1=1"
    params = []

    if user.get('role') == 'admin':
        query += " AND admin_id = %s"
        params.append(user.get('id'))
    # Owner sees all orders — no admin_id filter

    if status_filter:
        query += " AND status = %s"
        params.append(status_filter)

    if date_filter:
        try:
            # Ensure it's a valid date format
            datetime.strptime(date_filter, "%Y-%m-%d")
            query += " AND DATE(order_date) = %s"
            params.append(date_filter)
        except ValueError:
            flash("⚠️ Invalid date format. Use YYYY-MM-DD.", "error")

    query += " ORDER BY order_date DESC"

    cursor.execute(query, params)
    orders = cursor.fetchall()
    cursor.close()
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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for('orders'))

    if user['role'] == 'admin' and order['admin_id'] != user['id']:
        flash("You are not authorized to accept this order.", "error")
        conn.close()
        return redirect(url_for('orders'))

    accepted_at = datetime.now()  # ✅ Store as datetime object
    cursor.execute("""
        UPDATE orders 
        SET status = 'accepted', accepted_at = %s 
        WHERE id = %s
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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_email, status, admin_id FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

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

    cancelled_at = datetime.now()  # store as raw datetime
    cursor.execute("""
        UPDATE orders 
        SET status = 'cancelled', cancelled_at = %s 
        WHERE id = %s
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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT status, admin_id FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for("orders"))

    if user['role'] == 'admin' and order['admin_id'] != user['id']:
        flash("You are not authorized to deliver this order.", "error")
        conn.close()
        return redirect(url_for("orders"))

    if order['status'] == 'accepted':
        delivered_at = datetime.now()  # ✅ Correct: no formatting
        cursor.execute("""
            UPDATE orders 
            SET status = 'delivered', delivered_at = %s 
            WHERE id = %s
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
    if not user or user.get('role') != 'owner':
        flash("Unauthorized", "error")
        return redirect(url_for('home'))

    conn = get_mysql_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE id = %s", (order_id,))
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

        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO bills (name, contact, address1, address2, city, pincode, total, created_at, admin_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, contact, address1, address2, city, pincode, 0, created_at, user["id"]))
        bill_id = cursor.lastrowid

        items = []
        for key in request.form:
            if key.startswith("products_name_"):
                idx = key.split("_")[-1]
                item_name = request.form.get(key)
                qty = int(request.form.get(f"products_qty_{idx}") or 1)
                if item_name:
                    items.append(("products", item_name, qty))
            if key.startswith("service_name_"):
                idx = key.split("_")[-1]
                item_name = request.form.get(key)
                qty = int(request.form.get(f"service_qty_{idx}") or 1)
                if item_name:
                    items.append(("service", item_name, qty))

        total = 0
        for item_type, item_name, qty in items:
            db = get_mysql_connection()
            cur = db.cursor(dictionary=True)
            table = "products" if item_type == "products" else "services"
            cur.execute(f"SELECT price, discount_price FROM {table} WHERE name = %s", (item_name,))
            row = cur.fetchone()
            db.close()

            if row:
                price = float(row["discount_price"] or row["price"] or 0)
                total += price * qty
                cursor.execute("""
                    INSERT INTO bill_items (bill_id, item_type, item_name, quantity, price)
                    VALUES (%s, %s, %s, %s, %s)
                """, (bill_id, item_type, item_name, qty, price))

        cursor.execute("UPDATE bills SET total = %s WHERE id = %s", (round(total, 2), bill_id))
        conn.commit()
        conn.close()

        flash("✅ Bill saved successfully!", "success")
        return redirect(url_for("sales"))

    # === Online Orders ===
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    base_query = "SELECT * FROM orders"
    where_clause = ""
    params = []

    if user["role"] == "admin":
        where_clause = " WHERE admin_id = %s"
        params = [user["id"]]

    cursor.execute(base_query + where_clause + " ORDER BY order_date DESC", params)
    orders = cursor.fetchall()

    cursor.execute(f"SELECT COUNT(*) AS count FROM orders{where_clause}", params)
    total_orders = cursor.fetchone()["count"]

    cursor.execute(f"SELECT COUNT(*) AS count FROM orders WHERE status = 'delivered'" + (" AND admin_id = %s" if user["role"] == "admin" else ""), params)
    delivered_orders = cursor.fetchone()["count"]

    cursor.execute(f"SELECT COUNT(*) AS count FROM orders WHERE status = 'pending'" + (" AND admin_id = %s" if user["role"] == "admin" else ""), params)
    pending_orders = cursor.fetchone()["count"]

    cursor.execute(f"SELECT SUM(amount) AS total FROM orders WHERE status = 'delivered'" + (" AND admin_id = %s" if user["role"] == "admin" else ""), params)
    total_revenue = cursor.fetchone()["total"] or 0
    conn.close()

    # === Products ===
    conn_products = get_mysql_connection()
    cursor = conn_products.cursor(dictionary=True)
    if user["role"] == "admin":
        cursor.execute("SELECT * FROM products WHERE admin_id = %s", (user["id"],))
    else:
        cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn_products.close()

    # === Services ===
    conn_services = get_mysql_connection()
    cursor = conn_services.cursor(dictionary=True)
    if user["role"] == "admin":
        cursor.execute("SELECT * FROM services WHERE admin_id = %s", (user["id"],))
    else:
        cursor.execute("SELECT * FROM services")
    services = cursor.fetchall()
    conn_services.close()

    # === Offline Bills ===
    conn_bills = get_mysql_connection()
    cursor = conn_bills.cursor(dictionary=True)
    if user["role"] == "admin":
        cursor.execute("SELECT * FROM bills WHERE admin_id = %s ORDER BY created_at DESC", (user["id"],))
    else:
        cursor.execute("SELECT * FROM bills ORDER BY created_at DESC")
    offline_bills = cursor.fetchall()
    conn_bills.close()

    offline_revenue = sum(b["total"] for b in offline_bills if b["total"])
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

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT admin_id FROM bills WHERE id = %s", (bill_id,))
    bill = cursor.fetchone()

    if not bill:
        conn.close()
        flash("Bill not found.", "error")
        return redirect(url_for("sales"))

    if user["role"] != "owner" and bill["admin_id"] != user["id"]:
        conn.close()
        flash("You are not authorized to delete this bill.", "error")
        return redirect(url_for("sales"))

    cursor.execute("DELETE FROM bill_items WHERE bill_id = %s", (bill_id,))
    cursor.execute("DELETE FROM bills WHERE id = %s", (bill_id,))
    conn.commit()
    conn.close()

    flash("Bill deleted successfully.", "success")
    return redirect(url_for("sales"))

@app.route("/bill/print/<int:bill_id>")
def print_bill(bill_id):
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM bills WHERE id = %s", (bill_id,))
    bill = cursor.fetchone()

    if not bill:
        conn.close()
        flash("Bill not found.", "error")
        return redirect(url_for("sales"))

    if user["role"] != "owner" and bill["admin_id"] != user["id"]:
        conn.close()
        flash("Unauthorized to view this bill.", "error")
        return redirect(url_for("sales"))

    cursor.execute("SELECT * FROM bill_items WHERE bill_id = %s", (bill_id,))
    items_raw = cursor.fetchall()
    conn.close()

    final_items = []
    for item in items_raw:
        item_name = item["item_name"]
        item_type = item["item_type"]
        quantity = int(item["quantity"])

        conn_lookup = get_mysql_connection()
        cur_lookup = conn_lookup.cursor(dictionary=True)
        table = "products" if item_type == "products" else "services"
        cur_lookup.execute(f"SELECT price, discount_price FROM {table} WHERE name = %s", (item_name,))
        row = cur_lookup.fetchone()
        conn_lookup.close()

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

@app.route('/products', methods=['GET', 'POST'])
def products():
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
            return redirect(url_for('products'))

        upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
        os.makedirs(upload_folder, exist_ok=True)
        saved_filenames = []

        for img in images:
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                img_path = os.path.join(upload_folder, filename)
                img.save(img_path)
                saved_filenames.append(filename)

        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO products (name, description, price, discount_price, images, admin_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, description, price, discount_price, json.dumps(saved_filenames), user['id'])
        )
        conn.commit()
        conn.close()

        flash("products item added successfully!", "success")
        return redirect(url_for('products'))

    # GET: Fetch products based on role
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    if is_owner:
        cursor.execute("SELECT * FROM products ORDER BY id DESC")
    else:
        cursor.execute("SELECT * FROM products WHERE admin_id = %s ORDER BY id DESC", (user["id"],))
    
    rows = cursor.fetchall()
    conn.close()

    products_items = []
    for row in rows:
        try:
            images = json.loads(row["images"]) if row["images"] else []
        except Exception:
            images = []

        products_items.append({
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "price": row["price"],
            "discount_price": row["discount_price"],
            "images": images
        })

    return render_template(
        'products.html',
        user=user,
        full_name=full_name,
        products_items=products_items
    )

@app.route('/edit_products/<int:item_id>', methods=['POST'])
def edit_products(item_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("home"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT images, admin_id FROM products WHERE id = %s", (item_id,))
    row = cur.fetchone()

    if not row:
        flash("products not found.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("products"))

    if user["role"] == "admin" and row["admin_id"] != user["id"]:
        flash("You are not authorized to edit this products.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("products"))

    try:
        old_images = json.loads(row["images"]) if row["images"] else []
    except Exception:
        old_images = row["images"].split(',')

    name = request.form['name']
    description = request.form.get('description', '')
    price = request.form['price']
    discount_price = request.form['discount_price']
    uploaded_files = request.files.getlist('images')
    new_images = []

    upload_folder = os.path.join(current_app.root_path, "static/uploads/productss")
    os.makedirs(upload_folder, exist_ok=True)

    if uploaded_files and any(f.filename for f in uploaded_files):
        for img in old_images:
            try:
                os.remove(os.path.join(upload_folder, img))
            except Exception as e:
                print(f"Error deleting {img}: {e}")

        for file in uploaded_files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                new_images.append(filename)

        if len(new_images) > 5:
            flash("You can upload a maximum of 5 images.", "error")
            cur.close()
            conn.close()
            return redirect(url_for('products'))
    else:
        new_images = old_images

    cur.execute("""
        UPDATE products
        SET name = %s, description = %s, price = %s, discount_price = %s, images = %s
        WHERE id = %s
    """, (name, description, price, discount_price, json.dumps(new_images), item_id))

    conn.commit()
    cur.close()
    conn.close()

    flash("products updated successfully.", "success")
    return redirect(url_for('products'))


@app.route('/delete_products/<int:item_id>', methods=['POST'])
def delete_products(item_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized action.", "error")
        return redirect(url_for("home"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT images, admin_id FROM products WHERE id = %s", (item_id,))
    products = cur.fetchone()

    if not products:
        flash("products not found.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("products"))

    if user['role'] == 'admin' and products['admin_id'] != user['id']:
        flash("You are not authorized to delete this products.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("products"))

    try:
        image_list = json.loads(products["images"]) if products["images"] else []
    except Exception:
        image_list = products["images"].split(',')

    upload_folder = os.path.join(current_app.root_path, "static/uploads/products")
    for img_filename in image_list:
        img_path = os.path.join(upload_folder, img_filename.strip())
        if os.path.exists(img_path):
            try:
                os.remove(img_path)
            except Exception as e:
                print(f"Failed to delete image {img_path}: {e}")

    cur.execute("DELETE FROM products WHERE id = %s", (item_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("products deleted successfully.", "success")
    return redirect(url_for('products'))

@app.route("/services", methods=["GET", "POST"])
def services():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)

    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        discount_price = request.form.get("discount_price")
        description = request.form.get("description")

        image_url = None
        file = request.files.get("image")
        if file and file.filename:
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(current_app.root_path, "static/uploads/services")
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            image_url = f"/static/uploads/services/{filename}"

        cur.execute("""
            INSERT INTO services (name, price, discount_price, description, image_url, admin_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (name, price, discount_price, description, image_url, user["id"]))
        conn.commit()
        flash("Service added successfully!", "success")
        return redirect(url_for("services"))

    # Fetch services
    if user["role"] == "owner":
        cur.execute("SELECT * FROM services ORDER BY id DESC")
    else:
        cur.execute("SELECT * FROM services WHERE admin_id = %s ORDER BY id DESC", (user["id"],))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    services = []
    for row in rows:
        services.append({
            "id": row["id"],
            "name": row["name"],
            "price": row["price"],
            "discount_price": row.get("discount_price", "") or "",
            "description": row.get("description", "") or "",
            "image_url": row.get("image_url", "") or ""
        })

    return render_template("services.html", user=user, full_name=user["full_name"], services=services)


@app.route('/edit_service/<int:service_id>', methods=['POST'])
def edit_service(service_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("services"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM services WHERE id = %s", (service_id,))
    service = cur.fetchone()

    if not service or (user["role"] == "admin" and service["admin_id"] != user["id"]):
        flash("Unauthorized or service not found.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("services"))

    name = request.form.get("name")
    price = request.form.get("price")
    discount_price = request.form.get("discount_price")
    description = request.form.get("description")
    image_url = service["image_url"]

    file = request.files.get("image")
    if file and file.filename:
        filename = secure_filename(file.filename)
        upload_folder = os.path.join(current_app.root_path, "static/uploads/services")
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        image_url = f"/static/uploads/services/{filename}"

    cur.execute("""
        UPDATE services
        SET name = %s, price = %s, discount_price = %s, description = %s, image_url = %s
        WHERE id = %s
    """, (name, price, discount_price, description, image_url, service_id))
    conn.commit()
    cur.close()
    conn.close()

    flash("Service updated successfully.", "success")
    return redirect(url_for("services"))


@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    user = get_user()
    if not user or user.get("role") not in ["admin", "owner"]:
        flash("Unauthorized", "error")
        return redirect(url_for("services"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM services WHERE id = %s", (service_id,))
    service = cur.fetchone()

    if not service or (user["role"] == "admin" and service["admin_id"] != user["id"]):
        flash("Unauthorized to delete this service.", "error")
        cur.close()
        conn.close()
        return redirect(url_for("services"))

    cur.execute("DELETE FROM services WHERE id = %s", (service_id,))
    conn.commit()
    cur.close()
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
        return redirect("/mobile" if is_mobile else url_for("login_user", open_login="true"))

    if request.method == "POST":
        flash("Messaging system is disabled.", "info")

    return render_template("contact.html", full_name=user["full_name"], user=user)


@app.route("/settings")
def settings():
    user = get_user()

    if not user:
        flash("Please log in to access settings.", "login_error")
        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent
        return redirect("/mobile" if is_mobile else url_for("login_user", open_login="true"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM security_questions")
    questions = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("settings.html", user=user, full_name=user.get("full_name"), questions=questions)


@app.route("/delete-account", methods=["POST"])
def delete_account():
    user = get_user()
    if not user:
        return redirect(url_for("login_user"))

    email = user["email"]
    role = user.get("role", "")

    if role == "admin":
        flash("Admins cannot delete their account directly.", "error")
        return redirect(url_for("settings", admin_delete_blocked=1))
    elif role == "owner":
        flash("Owner account deletion is restricted.", "error")
        return redirect(url_for("settings", owner_delete_blocked=1))

    try:
        conn = get_mysql_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE email = %s", (email,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Delete Error:", e)
        flash("❌ Failed to delete account. Try again.", "error")
        return redirect(url_for("settings"))

    session.pop("user_id", None)
    session.pop("user", None)
    flash("✅ Your account has been deleted.", "success")
    return redirect(url_for("register"))


@app.route("/account", methods=["GET", "POST"])
def account():
    user = get_user()

    if not user:
        flash("Please log in to access your account.", "login_error")
        user_agent = request.headers.get('User-Agent', '').lower()
        is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent
        return redirect("/mobile" if is_mobile else url_for("login_user", open_login="true"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        gender_id = request.form.get("gender_id", 1)

        conn = get_mysql_connection()
        cur = conn.cursor()

        if 'remove_image' in request.form:
            cur.execute("UPDATE users SET profile_image = NULL WHERE id = %s", (user["id"],))

        image = request.files.get("image")
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            cur.execute("UPDATE users SET profile_image = %s WHERE id = %s", (filename, user["id"]))

        cur.execute("UPDATE users SET full_name = %s, gender_id = %s WHERE id = %s",
                    (full_name, gender_id, user["id"]))
        conn.commit()
        cur.close()
        conn.close()

        flash("Account updated successfully.", "success")
        return redirect(url_for("account"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM security_questions")
    questions = cur.fetchall()
    cur.close()
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

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT password, temp_password, temp_password_uses FROM users WHERE email = %s", (user["email"],))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("account"))

    db_password = row["password"]
    temp_password = row["temp_password"]
    temp_uses = row["temp_password_uses"] or 0

    is_real = check_password_hash(db_password, old_pw)
    is_temp = temp_password == old_pw and temp_uses < 2

    if is_real or is_temp:
        cur.execute("""
            UPDATE users 
            SET password = %s, temp_password = NULL, temp_password_uses = 0 
            WHERE email = %s
        """, (generate_password_hash(new_pw), user["email"]))
        conn.commit()
        flash("Password updated successfully.", "success")
    else:
        flash("Current password is incorrect.", "error")

    cur.close()
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

    conn = get_mysql_connection()
    cur = conn.cursor()

    if email and email != user["email"]:
        if not session.get("otp_verified"):
            flash("Please verify OTP before changing your email.", "error")
            cur.close()
            conn.close()
            return redirect(url_for("account"))
        cur.execute("UPDATE users SET email = %s WHERE id = %s", (email, user["id"]))
        session["user"]["email"] = email
        session.pop("otp_verified", None)
        session.pop("register_otp", None)
        session.pop("otp_expiry", None)

    if contact and contact != user["contact"]:
        cur.execute("UPDATE users SET contact = %s WHERE id = %s", (contact, user["id"]))
        session["user"]["contact"] = contact

    conn.commit()
    cur.close()
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

        conn = get_mysql_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE email = %s", (user["email"],))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            flash("User not found.", "error")
            return redirect(url_for("account"))

        user_id = row["id"]
        session["user_id"] = user_id

    question = request.form.get("question")
    answer = request.form.get("answer")

    if not question or not answer:
        flash("Please select a question and provide an answer.", "error")
        return redirect(url_for("account"))

    conn = get_mysql_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users 
        SET security_question = %s, security_answer = %s 
        WHERE id = %s
    """, (question, answer, user_id))
    conn.commit()
    cur.close()
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
            conn = get_mysql_connection()
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT * FROM users
                WHERE (email = %s OR contact = %s) AND security_question = %s AND security_answer = %s
            """, (email, contact, question, answer))
            user = cur.fetchone()

            if user:
                temp_password = "Temp@123"  # or use generate_temp_password()
                cur.execute("UPDATE users SET temp_password = %s, temp_password_uses = 0 WHERE id = %s",
                            (temp_password, user["id"]))
                conn.commit()
                flash(f"🔑 Your temporary password is <b>{temp_password}</b>. It can be used only 2 times. Please change your password after login.", "success")
            else:
                flash("User not found or incorrect security answer.", "error")

            cur.close()
            conn.close()

    # Fetch questions from MySQL (not from `security.db`)
    conn2 = get_mysql_connection()
    cur2 = conn2.cursor(dictionary=True)
    cur2.execute("SELECT * FROM security_questions")  # Assuming table is migrated to MySQL
    questions = cur2.fetchall()
    cur2.close()
    conn2.close()

    return render_template("forgot.html", questions=questions, temp_password=temp_password)

@app.route("/send-reset-otp", methods=["POST"])
def send_reset_otp():
    email = request.json.get("email", "").strip().lower()

    if not email:
        return jsonify(success=False, message="⚠️ Email is required.")

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify(success=False, message="❌ This email is not registered.")

    now = time.time()
    otp_expiry = session.get("otp_expiry", 0)

    if otp_expiry and now < otp_expiry:
        remaining = int((otp_expiry - now) // 60) + 1
        return jsonify(success=False, message=f"⚠️ OTP already sent. Try again in {remaining} minute(s).")

    otp = generate_random_otp()
    session["register_email"] = email
    session["register_otp"] = otp
    session["otp_expiry"] = now + 300  # 5 minutes
    session["otp_verified"] = False

    if send_otp_to_email(email, otp):
        return jsonify(success=True, message="✅ OTP has been sent to your email.")

    return jsonify(success=False, message="❌ Failed to send OTP. Please try again.")


@app.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp = data.get("otp", "").strip()

    saved_otp = session.get("register_otp")
    saved_email = session.get("register_email")
    expiry = session.get("otp_expiry", 0)

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

    if not email or not otp or not new_password or not confirm_password:
        flash("⚠️ All fields are required.", "error")
        return redirect(url_for("forgot"))

    if new_password != confirm_password:
        flash("❌ Passwords do not match.", "error")
        return redirect(url_for("forgot"))

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        flash("❌ Email does not exist.", "error")
        return redirect(url_for("forgot"))

    stored_otp = session.get("register_otp")
    stored_email = session.get("register_email")
    expiry = session.get("otp_expiry", 0)
    is_verified = session.get("otp_verified", False)

    if not stored_otp or not stored_email:
        cur.close()
        conn.close()
        flash("❌ No OTP found. Please request again.", "error")
        return redirect(url_for("forgot"))

    if email != stored_email:
        cur.close()
        conn.close()
        flash("❌ Email does not match the one used for OTP.", "error")
        return redirect(url_for("forgot"))

    if time.time() > expiry:
        cur.close()
        conn.close()
        flash("⌛ OTP has expired. Please request a new one.", "error")
        return redirect(url_for("forgot"))

    if otp != stored_otp:
        cur.close()
        conn.close()
        flash("❌ Incorrect OTP. Please try again.", "error")
        return redirect(url_for("forgot"))

    if not is_verified:
        cur.close()
        conn.close()
        flash("⚠️ Please verify your OTP before resetting the password.", "error")
        return redirect(url_for("forgot"))

    hashed_pw = generate_password_hash(new_password)
    try:
        cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        conn.commit()

        # Clear OTP session data
        session.pop("register_email", None)
        session.pop("register_otp", None)
        session.pop("otp_verified", None)
        session.pop("otp_expiry", None)

        flash("✅ Password reset successful. Please login.", "success")
    except Exception as e:
        print("Error resetting password:", e)
        flash("❌ Something went wrong. Please try again.", "error")
    finally:
        cur.close()
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

        if not full_name or not contact or not email or not password or not confirm_password:
            flash("All fields are required.", "register_error")
            return redirect(url_for("login_user"))

        if password != confirm_password:
            flash("Passwords do not match.", "register_error")
            return redirect(url_for("login_user"))

        # Optional: Check OTP verification
        if session.get("register_email") != email or not session.get("otp_verified"):
            flash("OTP verification failed or email mismatch.", "register_error")
            return redirect(url_for("login_user"))

        hashed_pw = generate_password_hash(password)

        try:
            conn = get_mysql_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (full_name, contact, email, password, role) VALUES (%s, %s, %s, %s, %s)",
                (full_name, contact, email, hashed_pw, 'user')
            )
            conn.commit()

            # Send welcome email
            send_user_welcome_email(email, full_name)
            flash("Registration successful. Please login.", "register_success")

            # Clear session after successful registration
            session.pop("register_email", None)
            session.pop("register_otp", None)
            session.pop("otp_expiry", None)
            session.pop("otp_verified", None)

        except mysql.connector.IntegrityError:
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
    email = request.json.get("email", "").strip().lower()
    if not email:
        return jsonify(success=False, message="Email is required.")

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        return jsonify(success=False, message="⚠️ Email already exists. Please log in instead.")

    now = time.time()
    expiry = session.get("otp_expiry", 0)
    if expiry and now < expiry:
        remaining = int((expiry - now) // 60)
        return jsonify(success=False, message=f"OTP already sent. Try again after {remaining} min.")

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

    if time.time() > expiry:
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

    conn = get_mysql_connection()
    cur = conn.cursor(dictionary=True)

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email').strip().lower()
        contact = request.form.get('contact')

        if not full_name or not email or not contact:
            flash("All fields are required.", "error")
            cur.close()
            conn.close()
            return redirect(url_for('create_admin'))

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Email already exists.", "error")
            cur.close()
            conn.close()
            return redirect(url_for('create_admin'))

        default_password = '1234'
        password_hash = generate_password_hash(default_password)

        try:
            cur.execute(
                "INSERT INTO users (full_name, email, contact, password, role) VALUES (%s, %s, %s, %s, %s)",
                (full_name, email, contact, password_hash, 'admin')
            )
            conn.commit()

            # Send welcome email
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

    cur.execute("SELECT id, full_name AS name, email, contact FROM users WHERE role = 'admin'")
    admins = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('create_admin.html', user=user, admins=admins)

@app.route('/delete_admin/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    user = get_user()
    if not user or user.get('role') not in ['admin', 'owner']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login_user'))

    conn = get_mysql_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s AND role = 'admin'", (admin_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("Admin deleted successfully.", "success")
    return redirect(url_for('create_admin'))

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("login_admin"))

        conn = get_mysql_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE LOWER(email) = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or not user.get("password"):
            flash("Invalid email or password", "error")
            return redirect(url_for("login_admin"))

        if not check_password_hash(user["password"], password):
            flash("Invalid email or password", "error")
            return redirect(url_for("login_admin"))

        if user["role"] not in ("admin", "owner"):
            flash("You are not authorized to log in as Admin/Owner.", "error")
            return redirect(url_for("login_admin"))

        session["user_id"] = user["id"]
        session["user"] = {
            "email": user["email"],
            "role": user["role"],
            "name": user["full_name"]
        }

        return redirect(url_for("home"))

    return render_template("login_admin.html")

@app.route("/logout")
def logout():
    user = session.get("user")
    role = user.get("role") if user else None

    # Clear session
    session.pop("user", None)
    session.pop("user_id", None)

    # Redirect admin/owner to admin login
    if role in ("admin", "owner"):
        return redirect(url_for("login_admin"))

    # Check for mobile user
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = "mobi" in user_agent or "android" in user_agent or "iphone" in user_agent

    # Redirect accordingly
    if is_mobile:
        return redirect("/mobile")
    return redirect(url_for("login_user", open_login="true"))

if __name__ == "__main__":
    app.run(debug=True)
