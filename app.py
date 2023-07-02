from flask import Flask, render_template, request, session, redirect
from flask_mysqldb import MySQL
from helpers import apology
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Create a secreat key for WTF
app.config['SECRET_KEY'] = "secretkey"

# Add Database
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'tasktrack'
 
mysql = MySQL(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
  return render_template('index.html')

@app.route("/register", methods=['POST', 'GET'])
def register():
  if request.method == "GET":
        return render_template("register.html")
    
  if request.method == "POST":
      cursor = mysql.connection.cursor()

      email = request.form.get("email")
      username = request.form.get("username")
      password = request.form.get("password")
      confirm_password = request.form.get("conform-password")

      # Check if username or password is empty
      if not username or not password:
          return apology("Invalid Username or Password: Blank")
      
      # Check if the passwords match
      if password != confirm_password:
          return apology("Invalid Password: Passwords do not match")
      
      # Check if username already exists
      cursor = mysql.connection.cursor()
      cursor.execute('SELECT username FROM users WHERE username = %s', (username,))
      existing_user = cursor.fetchone()
      if existing_user:
          cursor.close()
          return apology("Invalid Username: Username already exists")
      
      # Hash the password
      hashed_password = generate_password_hash(password)

      # Add to the database
      cursor.execute('INSERT INTO users (username, email, hash) VALUES (%s, %s, %s)', (username, email, hashed_password))
      mysql.connection.commit()
      cursor.close()
      return render_template("login.html")

@app.route("/login", methods=['POST', 'GET'])
def login():
  # Forget any user_id
  session.clear()

  # User reached route via POST (as by submitting a form via POST)
  if request.method == "POST":
      cursor = mysql.connection.cursor()

      # Ensure email was submitted
      if not request.form.get("email"):
          return apology("must provide email", 403)

      # Ensure password was submitted
      elif not request.form.get("password"):
          return apology("must provide password", 403)

      # Query database for email
      email = request.form.get("email")
      cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
      rows = cursor.fetchone()

      # Ensure email exists
      if rows == None:
          return apology("invalid email", 403)

      # Ensure username exists and password is correct
      if not check_password_hash(rows[-1], request.form.get("password")):
          cursor.close()
          return apology("invalid email and/or password", 403)

      # Remember which user has logged in
      session["user_id"] = rows[0]

      # Redirect user to home page
      return redirect("/dashbord")

  # User reached route via GET (as by clicking a link or via redirect)
  else:
      return render_template("login.html")
  
@app.route("/dashbord")
def dashbord():
    return render_template('dashbord.html')