# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from functools import wraps
from urllib.parse import quote
from datetime import datetime
from fpdf import FPDF
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "replace-this-with-a-secure-secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

### ---------- MODELS ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_owner = db.Column(db.Boolean, default=False)  # owner True, staff False

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    login_time = db.Column(db.String(50))
    logout_time = db.Column(db.String(50), nullable=True)
    # optional metadata (ip, device) can be added

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(120))
    phone = db.Column(db.String(30))
    notes = db.Column(db.String(255))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(120))
    price = db.Column(db.Float, default=0.0)
    quantity = db.Column(db.Integer, default=0)      # editable by staff (available qty)
    gst_percent = db.Column(db.Float, default=0.0)   # owner sets

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'))
    invoice_no = db.Column(db.String(50))
    subtotal = db.Column(db.Float, default=0.0)
    tax_total = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, default=0.0)
    date = db.Column(db.String(50))
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')
    # convenience relationship
    customer = db.relationship('Customer', lazy='joined')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)        # price at sale time
    gst_percent = db.Column(db.Float)  # gst percent at sale time
    product = db.relationship('Product', lazy='joined')

### ---------- HELPERS ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_owner():
    return User.query.filter_by(is_owner=True).first()


def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_owner:
            flash("Owner-only page", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def generate_invoice_number(user_id):
    last = Order.query.filter_by(user_id=user_id).order_by(Order.id.desc()).first()
    if not last or not last.invoice_no:
        num = 1
    else:
        try:
            parts = last.invoice_no.split('-')
            num = int(parts[-1]) + 1
        except:
            num = last.id + 1
    return f"INV-{user_id}-{str(num).zfill(4)}"

def generate_whatsapp_link(phone, message):
    phone = str(phone).replace(' ', '').replace('+', '')
    return f"https://wa.me/{phone}?text={quote(message)}"

def build_whatsapp_bill(order, cancelled=False):
    cust = order.customer
    lines = []
    if cancelled:
        lines.append("Previous bill cancelled. New bill below.")
        lines.append("")
    lines.append(f"{current_user.business_name or 'Business'}")
    lines.append(f"{cust.name} ({cust.phone})")
    lines.append("-" * 40)
    lines.append(f"{'Item'.ljust(22)} {'Qty'.ljust(5)} {'₹'}")
    lines.append("-" * 40)
    for it in order.items:
        total_line = it.price * it.quantity
        lines.append(f"{it.product.name.ljust(22)} {str(it.quantity).ljust(5)} {str(round(total_line,2)).rjust(6)}")
    lines.append("-" * 40)
    lines.append(f"{'Subtotal'.ljust(27)} ₹{order.subtotal:.2f}")
    lines.append(f"{'GST'.ljust(27)} ₹{order.tax_total:.2f}")
    lines.append(f"{'Total'.ljust(27)} ₹{order.total_amount:.2f}")
    lines.append(f"Invoice: {order.invoice_no}")
    lines.append(f"Date: {order.date}")
    return "\n".join(lines)

### ---------- AUTH ROUTES ----------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/')
def home_select():
    return render_template('home.html')

@app.route('/login_owner', methods=['GET', 'POST'])
def login_owner():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email, is_owner=True).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # Log login time
            log = LoginLog(user_id=user.id, login_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))

        flash("Invalid owner credentials", "danger")

    return render_template('login.html', role='owner')

@app.route('/login_staff', methods=['GET', 'POST'])
def login_staff():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email, is_owner=False).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)

            log = LoginLog(user_id=user.id,
                           login_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            db.session.add(log)
            db.session.commit()

            # staff goes directly to staff product list
            return redirect(url_for('products_staff'))

        flash("Invalid staff credentials", "danger")

    return render_template('login.html', role='staff')

@app.route('/staff/products')
@login_required
def products_staff():
    owner = get_owner()
    products = Product.query.filter_by(user_id=owner.id).all()
    return render_template('products_staff.html', products=products)

@app.route('/register', methods=['GET','POST'])
def register():
    # Only used for initial owner creation or disabled in production.
    if request.method == 'POST':
        business_name = request.form.get('business_name') or "My Business"
        email = request.form['email']
        password = request.form['password']
        is_owner = True if request.form.get('is_owner') == 'on' else False
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for('register'))
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        u = User(business_name=business_name, email=email, password=hashed, is_owner=is_owner)
        db.session.add(u)
        db.session.commit()
        flash("Account created. Please login", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        pw = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, pw):
            login_user(user)
            # record login time
            log = LoginLog(user_id=user.id, login_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            db.session.add(log)
            db.session.commit()
            # store login_log id in session so we can update logout later
            # We can't access session directly here because flask_login uses cookies,
            # but we can update logout in logout route by finding last open log.
            flash("Logged in", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # find last login log for this user which has no logout_time and set it
    log = LoginLog.query.filter_by(user_id=current_user.id, logout_time=None).order_by(LoginLog.id.desc()).first()
    if log:
        log.logout_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.session.commit()
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('login'))

### ---------- OWNER creates staff ----------
@app.route('/owner/create_staff', methods=['GET','POST'])
@login_required
@owner_required
def create_staff():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form.get('business_name', current_user.business_name)
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for('create_staff'))
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        staff = User(business_name=name, email=email, password=hashed, is_owner=False)
        db.session.add(staff)
        db.session.commit()
        flash("Staff account created", "success")
        return redirect(url_for('create_staff'))
    staff_list = User.query.filter_by(is_owner=False).all()
    return render_template('create_staff.html', staff_list=staff_list)

@app.route('/admin/logs')
@login_required
@owner_required
def admin_logs():
    logs = db.session.query(LoginLog, User).join(User, LoginLog.user_id == User.id)\
            .order_by(LoginLog.id.desc()).all()

    # Prepare data with duration
    log_data = []
    for log, user in logs:
        if log.logout_time:
            t1 = datetime.strptime(log.login_time, "%Y-%m-%d %H:%M:%S")
            t2 = datetime.strptime(log.logout_time, "%Y-%m-%d %H:%M:%S")
            duration = str(t2 - t1)
        else:
            duration = "Active"

        log_data.append({
            "email": user.email,
            "login": log.login_time,
            "logout": log.logout_time or "—",
            "duration": duration
        })

    return render_template("admin_logs.html", logs=log_data)


### ---------- DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():
    # Owner gets owner dashboard, staff gets staff dashboard
    if current_user.is_owner:
        customers = Customer.query.filter_by(user_id=current_user.id).all()
        products = Product.query.filter_by(user_id=current_user.id).all()
        orders = Order.query.filter_by(user_id=current_user.id).all()
        total_sales = sum(o.total_amount for o in orders)
        low_stock = [p for p in products if p.quantity <= 5]
        # simple top sellers
        top = {}
        for o in orders:
            for it in o.items:
                top[it.product.name] = top.get(it.product.name, 0) + it.quantity
        top_sellers = sorted(top.items(), key=lambda x: x[1], reverse=True)[:5]
        return render_template('dashboard_owner.html',
                                total_sales=total_sales,
                                total_orders=len(orders),
                                total_products=len(products),
                                total_customers=len(customers),
                                low_stock=low_stock,
                                top_sellers=top_sellers)
    else:
        # staff view
        products = Product.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard_staff.html', products=products)

### ---------- CUSTOMER ----------
@app.route('/customers')
@login_required
def customers():
    customers = Customer.query.filter_by(user_id=current_user.id).all()
    return render_template('customers.html', customers=customers)

@app.route('/add_customer', methods=['GET','POST'])
@login_required
def add_customer():
    if request.method=='POST':
        name = request.form['name']
        phone = request.form['phone']
        c = Customer(user_id=current_user.id, name=name, phone=phone, notes=request.form.get('notes',''))
        db.session.add(c)
        db.session.commit()
        flash("Customer added", "success")
        return redirect(url_for('customers'))
    return render_template('add_customer.html')

@app.route('/get_customer_by_phone')
@login_required
def get_customer_by_phone():
    phone = request.args.get('phone','').strip()
    if not phone:
        return jsonify({'name':''})
    c = Customer.query.filter_by(user_id=current_user.id, phone=phone).first()
    if c:
        return jsonify({'name':c.name})
    return jsonify({'name':''})

### ---------- PRODUCT ----------
@app.route('/products', methods=['GET'])
@login_required
def products():
    q = request.args.get('q','')
    if q:
        products = Product.query.filter(Product.user_id==current_user.id, Product.name.ilike(f"%{q}%")).all()
    else:
        products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('products.html', products=products, q=q)

@app.route('/add_product', methods=['GET','POST'])
@login_required
@owner_required
def add_product():
    if request.method=='POST':
        name = request.form['name']
        price = float(request.form['price'] or 0)
        qty = int(request.form['quantity'] or 0)
        gst = float(request.form.get('gst_percent') or 0)
        p = Product(user_id=current_user.id, name=name, price=price, quantity=qty, gst_percent=gst)
        db.session.add(p)
        db.session.commit()
        flash("Product added", "success")
        return redirect(url_for('products'))
    return render_template('add_product.html')

@app.route('/edit_product/<int:id>', methods=['GET','POST'])
@login_required
def edit_product(id):
    p = Product.query.get_or_404(id)
    # Only owner may edit name/price/gst. Staff may update quantity only.
    if request.method=='POST':
        if current_user.is_owner:
            p.name = request.form['name']
            p.price = float(request.form['price'] or 0)
            p.gst_percent = float(request.form.get('gst_percent') or 0)
            p.quantity = int(request.form.get('quantity') or p.quantity)
            db.session.commit()
            flash("Product updated", "success")
            return redirect(url_for('products'))
        else:
            # staff can only update quantity
            p.quantity = int(request.form.get('quantity') or p.quantity)
            db.session.commit()
            flash("Quantity updated", "success")
            return redirect(url_for('dashboard'))
    return render_template('edit_product.html', product=p)

@app.route('/api/search_products')
@login_required
def search_products():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])

    owner = get_owner()

    results = Product.query.filter(
    Product.user_id == owner.id,
    Product.name.ilike(f"%{q}%")
).limit(10).all()


    return jsonify([
        {
            "id": p.id,
            "name": p.name,
            "price": p.price,
            "gst": p.gst_percent,
            "available": p.quantity
        }
        for p in results
    ])


@app.route('/delete_product/<int:id>')
@login_required
@owner_required
def delete_product(id):
    p = Product.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    flash("Deleted", "info")
    return redirect(url_for('products'))

### ---------- ORDERS ----------
@app.route('/orders')
@login_required
def orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('orders.html', orders=orders)

@app.route('/add_order', methods=['GET','POST'])
@login_required
def add_order():
    # Both staff and owner can add orders (owner usually does too)
    owner = get_owner()
    products = Product.query.filter_by(user_id=owner.id).all()

    if request.method == 'POST':
        cust_name = request.form['customer_name']
        cust_phone = request.form['customer_phone']
        # find or create customer
        customer = Customer.query.filter_by(user_id=current_user.id, phone=cust_phone).first()
        if not customer:
            customer = Customer(user_id=current_user.id, name=cust_name, phone=cust_phone)
            db.session.add(customer)
            db.session.commit()

        order = Order(user_id=current_user.id, customer_id=customer.id,
                      subtotal=0.0, tax_total=0.0, total_amount=0.0,
                      date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        db.session.add(order)
        db.session.commit()

        subtotal = 0.0
        tax_total = 0.0
        # loop over products and read qty_{id}
        for p in products:
            qty_raw = request.form.get(f"qty_{p.id}", "0")
            try:
                qty = int(qty_raw)
            except:
                qty = 0
            if qty and qty > 0:
                if p.quantity < qty:
                    flash(f"Not enough stock for {p.name}. Available {p.quantity}", "danger")
                    db.session.delete(order)
                    db.session.commit()
                    return redirect(url_for('add_order'))
                # deduct stock
                p.quantity -= qty
                line_sub = p.price * qty
                line_gst = (p.gst_percent or 0.0) * line_sub / 100.0
                oi = OrderItem(order_id=order.id, product_id=p.id, quantity=qty, price=p.price, gst_percent=p.gst_percent or 0.0)
                db.session.add(oi)
                subtotal += line_sub
                tax_total += line_gst

        order.subtotal = round(subtotal,2)
        order.tax_total = round(tax_total,2)
        order.total_amount = round(subtotal + tax_total,2)
        order.invoice_no = generate_invoice_number(current_user.id)
        db.session.commit()
        flash("Order created", "success")
        return redirect(url_for('order_summary', order_id=order.id))
    return render_template('add_order.html', products=products)

@app.route('/edit_order/<int:id>', methods=['GET','POST'])
@login_required
def edit_order(id):
    order = Order.query.get_or_404(id)
    # restore previous stock first
    for old_item in order.items:
        pr = Product.query.get(old_item.product_id)
        pr.quantity += old_item.quantity
    if request.method=='POST':
        cust_name = request.form['customer_name']
        cust_phone = request.form['customer_phone']
        customer = Customer.query.get(order.customer_id)
        customer.name = cust_name
        customer.phone = cust_phone
        # delete old items
        for it in order.items:
            db.session.delete(it)
        db.session.commit()
        # add new items
        owner = get_owner()
        products = Product.query.filter_by(user_id=owner.id).all()

        subtotal = 0.0
        tax_total = 0.0
        for p in products:
            qty_raw = request.form.get(f"qty_{p.id}", "0")
            try:
                qty = int(qty_raw)
            except:
                qty = 0
            if qty and qty > 0:
                if p.quantity < qty:
                    flash("Not enough stock", "danger")
                    return redirect(url_for('edit_order', id=id))
                p.quantity -= qty
                line_sub = p.price * qty
                line_gst = (p.gst_percent or 0.0) * line_sub / 100.0
                new_item = OrderItem(order_id=order.id, product_id=p.id, quantity=qty, price=p.price, gst_percent=p.gst_percent or 0.0)
                db.session.add(new_item)
                subtotal += line_sub
                tax_total += line_gst
        order.subtotal = round(subtotal,2)
        order.tax_total = round(tax_total,2)
        order.total_amount = round(subtotal + tax_total,2)
        order.date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.session.commit()
        flash("Order updated", "success")
        # when editing an order we will show summary page and allow WhatsApp with cancellation message
        return redirect(url_for('order_summary', order_id=order.id, cancelled='1'))
    products = Product.query.filter_by(user_id=current_user.id).all()
    item_qty = {it.product_id: it.quantity for it in order.items}
    customer = Customer.query.get(order.customer_id)
    return render_template('edit_order.html', order=order, products=products, item_qty=item_qty, customer=customer)

@app.route('/delete_order/<int:id>')
@login_required
def delete_order(id):
    order = Order.query.get_or_404(id)
    if order.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for('orders'))
    # restore stock
    for it in order.items:
        p = Product.query.get(it.product_id)
        p.quantity += it.quantity
    db.session.delete(order)
    db.session.commit()
    flash("Order deleted and stock restored", "info")
    return redirect(url_for('orders'))

@app.route('/order_summary/<int:order_id>')
@login_required
def order_summary(order_id):
    order = Order.query.get_or_404(order_id)
    cancelled = True if request.args.get('cancelled') == '1' else False
    whatsapp_text = build_whatsapp_bill(order, cancelled=cancelled)
    whatsapp_link = generate_whatsapp_link(order.customer.phone, whatsapp_text)
    return render_template('order_summary.html', order=order, whatsapp_link=whatsapp_link, cancelled=cancelled)

### ---------- PRINT PDF using FPDF ----------
@app.route('/print_bill/<int:order_id>')
@login_required
def print_bill(order_id):
    order = Order.query.get_or_404(order_id)
    customer = Customer.query.get(order.customer_id)
    items = order.items

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, current_user.business_name or "Business", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Customer: {customer.name} ({customer.phone})", ln=True)
    pdf.cell(0, 8, f"Invoice: {order.invoice_no}", ln=True)
    pdf.cell(0, 8, f"Date: {order.date}", ln=True)
    pdf.ln(4)
    pdf.cell(0, 5, "-"*60, ln=True)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(80,8,"Item")
    pdf.cell(25,8,"Qty")
    pdf.cell(35,8,"Price")
    pdf.cell(35,8,"Total", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(0,4,"-"*60, ln=True)
    for it in items:
        line_total = it.price * it.quantity
        pdf.cell(80,8,str(it.product.name))
        pdf.cell(25,8,str(it.quantity))
        pdf.cell(35,8,f"{it.price:.2f}")
        pdf.cell(35,8,f"{line_total:.2f}", ln=True)
    pdf.cell(0,4,"-"*60, ln=True)
    pdf.ln(4)
    pdf.set_font("Arial","B",14)
    pdf.cell(0,10,f"Subtotal: ₹{order.subtotal:.2f}", ln=True)
    pdf.cell(0,10,f"GST: ₹{order.tax_total:.2f}", ln=True)
    pdf.cell(0,10,f"TOTAL: ₹{order.total_amount:.2f}", ln=True)

    path = os.path.join(BASE_DIR, f"bill_{order.id}.pdf")
    pdf.output(path)
    return send_file(path, as_attachment=True)

### ---------- SETUP / MAIN ----------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )

