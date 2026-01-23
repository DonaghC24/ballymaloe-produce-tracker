# https://flask.palletsprojects.com
# PRIMARY SOURCE FOR ROUTING, RENDERING TEMPLATES, HANDLING FORMS, REDIRECING ETC...

import os  # environment variables
# Core Flask tools for app setup, templates, forms, redirects, and messages
from flask import Flask, render_template, request, redirect, url_for, flash

# Flask-Login tools for user sessions and route protection
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required 
)

# to securely hash passwords and verify them during login - https://werkzeug.palletsprojects.com
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv  # loads environment variables from a .env file

#
#
# all supabase content retreieved from - https://supabase.com/docs/reference/python/introduction
#
#

from models import User               #imports the custom User class for authentication and session handling
from supabase_client import supabase               #imports Supabase for database operations

load_dotenv()              # loads environment variables from .env file into the app

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "your-flask-secret-key")   #sets the secret key for session security, loads from environment


# https://flask-login.readthedocs.io/en/latest/
    login_manager = LoginManager()           # manages user login sessions
    login_manager.init_app(app)              # links login manager to the Flask app
    login_manager.login_view = "login"       # redirects unauthenticated users to the login page

    # https://supabase.com/docs/reference/python/introduction
    @login_manager.user_loader
    def load_user(user_id):               # fetches a single user record from the supabase 'users' table where id matches user_id
        response = supabase.table("users").select("*").eq("id", user_id).single().execute()
        if response.data:
            return User.from_supabase(response.data)        # converts the supabase user data into a flask-login User object
        return None

    # majority of route work is my own (past projects etc.), with some custom changes noted in comments where relevant.
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            # redirects logged-in users to admin or profile page based on role
            return redirect(url_for("admin_users") if current_user.is_admin else url_for("profile"))
        # redirects unauthenticated users to login page
        return redirect(url_for("login"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    # -- authorisation
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()   # retrieves and cleans the email input
            password = request.form.get("password", "")         # gets the password input

            # checks for missing input and shows error if either field is empty
            if not email or not password:
                flash("Email and password are required.", "danger")
                return redirect(url_for("register"))

            # checks if email is already in use and blocks duplicate registration
            existing = supabase.table("users").select("id").eq("email", email).execute()
            if existing.data:
                flash("Email already registered.", "warning")
                return redirect(url_for("register"))

            # checks if this is the first user in the system to auto-assign admin role
            first_user = not supabase.table("users").select("id").limit(1).execute().data
            # creates a new user dictionary with hashed password and role
            new_user = {
                "email": email,
                "password_hash": generate_password_hash(password),
                "is_admin": first_user
            }
            # inserts the new user into the database
            supabase.table("users").insert(new_user).execute()
            # confirms registration and redirects to login.
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])      #same as above
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            # queries the 'users' table for a record matching the given email
            response = supabase.table("users").select("*").eq("email", email).execute()
            # extracts the first matching user record, or sets to none if no match found
            user_data = response.data[0] if response.data else None

            if user_data and check_password_hash(user_data["password_hash"], password):
                # creates a user object from the database record
                user = User.from_supabase(user_data)
                # logs the user in and starts a session
                login_user(user)
                flash("Logged in.", "success")
                # redirects to admin dashboard or profile based on user role
                return redirect(url_for("admin_users") if user.is_admin else url_for("profile"))

            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    # ---admin-only user management
    def require_admin():
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return False
        return True

    @app.route("/admin/users")
    @login_required
    def admin_users():
        if not require_admin():
            return redirect(url_for("index"))   # redirects if user is not an admin
        # fetches all users from the database, ordered by creation date (newest first)
        response = supabase.table("users").select("*").order("created_at", desc=True).execute()
        users = [User.from_supabase(u) for u in response.data] # converts each user record into a User object
        return render_template("admin_users.html", users=users)  # renders the admin user management page with the list of users

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    def delete_user(user_id):
        if not require_admin():
            return redirect(url_for("index"))   # redirects if user is not an admin

        response = supabase.table("users").select("*").eq("id", user_id).single().execute()
        user_data = response.data         # fetches the user record to be deleted

        # prevent unsafe or invalid user deletion:
        if not user_data:
            flash("User not found.", "danger")
            return redirect(url_for("admin_users"))

        if user_data["id"] == current_user.id:
            flash("You cannot delete yourself.", "warning")
            return redirect(url_for("admin_users"))
        if user_data["is_admin"]:
            flash("Cannot delete the admin account.", "warning")
            return redirect(url_for("admin_users"))

        # deletes the user from the database
        supabase.table("users").delete().eq("id", user_id).execute()
        # confirms deletion and reloads the admin user lis
        flash(f"Deleted user {user_data['email']}.", "success")
        return redirect(url_for("admin_users"))


    @app.route("/harvests")
    @login_required
    def view_harvests():
        # Fetch all harvest records, ordered by harvest date
        harvest_response = supabase.table("harvests").select("*, users(email)").order("harvested_on",desc=True).execute()
        harvests = harvest_response.data if harvest_response.data else []

        # Fetch all produce types for filtering or display
        produce_response = supabase.table("produce_types").select("*").execute()
        produce_types = produce_response.data if produce_response.data else []

        return render_template("harvests.html", harvests=harvests, produce_types=produce_types)

    @app.route("/harvests/new", methods=["GET", "POST"])
    @login_required
    def new_harvest():
        if request.method == "POST":
            # gets and cleans inputs below
            crop_name = request.form.get("crop_name", "").strip()
            quantity = request.form.get("quantity", "").strip()
            unit = request.form.get("unit", "").strip()
            harvested_on = request.form.get("harvested_on", "").strip()

            # checks that required fields are filled in, excluding the optional date
            if not crop_name or not quantity or not unit:
                flash("All fields except date are required.", "danger")
                return redirect(url_for("new_harvest"))
            # ensures quantity input is a valid number
            try:
                quantity = float(quantity)
            except ValueError:
                flash("Quantity must be a number.", "danger")
                return redirect(url_for("new_harvest"))

            # builds a dictionary with harvest details and the user who entered it
            harvest_data = {
                "crop_name": crop_name,
                "quantity": quantity,
                "unit": unit,
                "entered_by": current_user.id
            }

            if harvested_on:
                harvest_data["harvested_on"] = harvested_on
            # inserts the harvest record into the database
            supabase.table("harvests").insert(harvest_data).execute()
            flash("Harvest logged successfully.", "success")
            return redirect(url_for("new_harvest"))

        # this asks Supabase for all rows in the 'produce_types' table, but only selects the name and category columns.
        # reference for block of code:  https://supabase.com/docs/reference/python/select
        produce_response = supabase.table("produce_types").select("name", "category").execute()
        produce_types = produce_response.data if produce_response.data else []

        return render_template("new_harvest.html", produce_types=produce_types)

    @app.route("/orders/new", methods=["GET", "POST"])
    @login_required
    def new_order():
        if request.method == "POST":
            # get form inputs from the submitted order form -
            produce_name = request.form.get("produce_name", "").strip()
            quantity = request.form.get("quantity", "").strip()
            unit = request.form.get("unit", "").strip()
            ordered_on = request.form.get("ordered_on", "").strip()
            notes = request.form.get("notes", "").strip()
            # validate required fields
            if not produce_name or not quantity or not unit:
                flash("Produce, quantity, and unit are required.", "danger")
                return redirect(url_for("new_order"))
            # ensure quantity is numeric
            try:
                quantity = float(quantity)
            except ValueError:
                flash("Quantity must be a number.", "danger")
                return redirect(url_for("new_order"))

            order_data = {
                "produce_name": produce_name,
                "quantity": quantity,
                "unit": unit,
                "ordered_by": current_user.id
            }

            if ordered_on:
                order_data["ordered_on"] = ordered_on
            if notes:
                order_data["notes"] = notes
            # insert new order into 'orders' table
            supabase.table("orders").insert(order_data).execute()
            flash("Order placed successfully.", "success")
            return redirect(url_for("view_orders"))

        # Fetch produce types for dropdown
        produce_response = supabase.table("produce_types").select("name", "category").execute()
        produce_types = produce_response.data if produce_response.data else []
        return render_template("new_order.html", produce_types=produce_types)



    # iteration 2 new orders route
    @app.route("/orders")
    @login_required
    def view_orders():
        order_response = supabase.table("orders").select("*, users(email)").order("ordered_on", desc=True).execute()
        orders = order_response.data if order_response.data else []
        return render_template("orders.html", orders=orders)









#------------------------------------------------
# ITERATION 3 AS FAR AS LINE 392
    # Reference:
    # Flask Quickstart — Routing, Redirects, Flashing
    # https://flask.palletsprojects.com/en/3.0.x/quickstart/
    @app.route("/orders/<int:order_id>/delete", methods=["POST"])

    #Reference:
    #Flask‑Login — Protecting
    #Views & current_user
    #https://flask-login.readthedocs.io/en/latest/
    @login_required
    def delete_order(order_id):
        #Reference:
        #Supabase
        #Python
        #Client — Select & Delete
        #https://supabase.com/docs/reference/python/select
        # fetching order to ensure it exists
        response = supabase.table("orders").select("*").eq("id", order_id).single().execute()
        order = response.data

        if not order:
            flash("Order not found.", "danger")
            return redirect(url_for("view_orders"))

        # permission check: users can only delete their own orders but admins can delete any order
        if order["ordered_by"] != current_user.id and not current_user.is_admin:
            flash("You do not have permission to delete this order.", "danger")
            return redirect(url_for("view_orders"))

        # Delete the order in supabase
        supabase.table("orders").delete().eq("id", order_id).execute()

        flash("Order cancelled.", "success")
        return redirect(url_for("view_orders"))


    #Reference:
    #Flask
    #https: // flask.palletsprojects.com / en / 3.0.x / quickstart /
    # Covers:
    # request.method == "POST", request.form.get(), flash(), redirect(), url_for(), render_template()



    #Reference:
    #Flask‑Login
    #Views & current_user
    #https: // flask - login.readthedocs.io / en / latest /
    # Covers: current_user.id, current_user.is_admin
    @app.route("/orders/<int:order_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_order(order_id):

        #Covers: .table("orders"), .select("*"), .eq("id", order_id), .single(), .update(update_data), .execute()
        # Fetching produce types
        #Reference:
        #https: // supabase.com / docs / reference / python / select
        # fetch the order
        response = supabase.table("orders").select("*").eq("id", order_id).single().execute()
        order = response.data

        if not order:
            flash("Order not found.", "danger")
            return redirect(url_for("view_orders"))

        # permission check again
        if order["ordered_by"] != current_user.id and not current_user.is_admin:
            flash("You do not have permission to edit this order.", "danger")
            return redirect(url_for("view_orders"))

        # -----------------------------   Handle form submission (POST) -----------------------------
        # .strip(): Return a copy of the string with leading and trailing whitespace removed.
        if request.method == "POST":
            produce_name = request.form.get("produce_name", "").strip()
            quantity = request.form.get("quantity", "").strip()
            unit = request.form.get("unit", "").strip()
            ordered_on = request.form.get("ordered_on", "").strip()
            notes = request.form.get("notes", "").strip()

            # Validation
            # ensure required fields are not empty
            if not produce_name or not quantity or not unit:
                flash("Produce, quantity, and unit are required.", "danger")
                return redirect(url_for("edit_order", order_id=order_id))

            # Ensure value is numeric
            try:
                quantity = float(quantity)
            except ValueError:
                flash("Quantity must be a number.", "danger")
                return redirect(url_for("edit_order", order_id=order_id))

            # dictionary of updated fields
            update_data = {
                "produce_name": produce_name,
                "quantity": quantity,
                "unit": unit,
                "notes": notes
            }

            if ordered_on:
                update_data["ordered_on"] = ordered_on

            # Update the order in Supabase -----------------------------
            supabase.table("orders").update(update_data).eq("id", order_id).execute()

            flash("Order updated successfully.", "success")
            return redirect(url_for("view_orders"))

        # GET request -> show form
        produce_response = supabase.table("produce_types").select("name", "category").execute()
        produce_types = produce_response.data if produce_response.data else []

        return render_template("edit_order.html", order=order, produce_types=produce_types)




    # Reference:
    # Flask Quickstart — Routing, Request Data, Redirects, Flashing, Templates
    # https://flask.palletsprojects.com/en/3.0.x/quickstart/
# Covers: @app.route(..., methods=["GET", "POST"]), request.method == "POST", request.form.get(), flash(), redirect(), url_for(), render_template()
    @app.route("/produce/new", methods=["GET", "POST"])
#Reference:
# Flask‑Login — Protecting Views & current_user
# https://flask-login.readthedocs.io/en/latest/
    @login_required
    def new_produce():
        # admin-only access
        if not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "").strip()

            # Validation
            if not name or not category:
                flash("Name and category are required.", "danger")
                return redirect(url_for("new_produce"))


#Reference:
#Supabase Python Client — Select
#https://supabase.com/docs/reference/python/select
            # check for duplicates
            existing = supabase.table("produce_types").select("id").eq("name", name).execute()
            if existing.data:
                flash("This produce type already exists.", "warning")
                return redirect(url_for("new_produce"))

            # put into database
            supabase.table("produce_types").insert({
                "name": name,
                "category": category
            }).execute()

            flash("New produce type added.", "success")
            return redirect(url_for("new_produce"))

        return render_template("new_produce.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
