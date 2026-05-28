from flask import (
    Flask,
    request,
    redirect,
    session
)

app = Flask(__name__)

app.secret_key = "shadowxss"


# -----------------------------
# Fake Database
# -----------------------------

comments_db = []


# -----------------------------
# Home Page
# -----------------------------

@app.route("/")
def home():

    username = session.get(
        "username",
        "Guest"
    )

    return f"""
    <html>

    <head>

        <title>ShadowXSS Lab</title>

        <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

    </head>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1 class="mb-4">
            ShadowXSS Vulnerable Lab
        </h1>

        <p>
            Logged in as:
            <b>{username}</b>
        </p>

        <div class="list-group">

            <a href="/search"
            class="list-group-item list-group-item-action">
                Search Page
            </a>

            <a href="/profile"
            class="list-group-item list-group-item-action">
                Profile Page
            </a>

            <a href="/comments"
            class="list-group-item list-group-item-action">
                Comments Page
            </a>

            <a href="/contact"
            class="list-group-item list-group-item-action">
                Contact Page
            </a>

            <a href="/login"
            class="list-group-item list-group-item-action">
                Login Page
            </a>

            <a href="/dom"
            class="list-group-item list-group-item-action">
                DOM XSS Page
            </a>

        </div>

    </div>

    </body>
    </html>
    """


# -----------------------------
# Login Page
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        session["username"] = username

        return redirect("/")

    return """
    <html>

    <head>

    <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

    </head>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>Login</h1>

        <form method="POST">

            <input
            class="form-control mb-3"
            name="username"
            placeholder="Username">

            <button
            class="btn btn-primary">
                Login
            </button>

        </form>

    </div>

    </body>
    </html>
    """


# -----------------------------
# Reflected XSS
# -----------------------------

@app.route("/search")
def search():

    q = request.args.get("q", "")

    return f"""
    <html>

    <head>

    <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

    </head>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>Search</h1>

        <form>

            <input
            class="form-control mb-3"
            name="q"
            placeholder="Search">

            <button
            class="btn btn-success">
                Search
            </button>

        </form>

        <div class="alert alert-info mt-3">

            Results for:
            {q}

        </div>

    </div>

    </body>
    </html>
    """


# -----------------------------
# Profile Page
# -----------------------------

@app.route("/profile")
def profile():

    name = request.args.get(
        "name",
        ""
    )

    return f"""
    <html>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>Profile</h1>

        <h3>
            Welcome {name}
        </h3>

    </div>

    </body>
    </html>
    """


# -----------------------------
# Stored XSS
# -----------------------------

@app.route("/comments", methods=["GET", "POST"])
def comments():

    if request.method == "POST":

        comment = request.form.get(
            "comment"
        )

        comments_db.append(comment)

    rendered_comments = ""

    for comment in comments_db:

        rendered_comments += f"""
        <div class='alert alert-warning'>
            {comment}
        </div>
        """

    return f"""
    <html>

    <head>

    <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

    </head>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>Comments</h1>

        <form method="POST">

            <textarea
            class="form-control mb-3"
            name="comment"></textarea>

            <button
            class="btn btn-danger">
                Post Comment
            </button>

        </form>

        <hr>

        {rendered_comments}

    </div>

    </body>
    </html>
    """


# -----------------------------
# Contact Form
# -----------------------------

@app.route("/contact", methods=["GET", "POST"])
def contact():

    message = ""

    if request.method == "POST":

        message = request.form.get(
            "message"
        )

    return f"""
    <html>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>Contact</h1>

        <form method="POST">

            <input
            class="form-control mb-3"
            name="message">

            <button
            class="btn btn-primary">
                Send
            </button>

        </form>

        <div class="mt-3">
            {message}
        </div>

    </div>

    </body>
    </html>
    """


# -----------------------------
# DOM XSS
# -----------------------------

@app.route("/dom")
def dom():

    return """
    <html>

    <body class="bg-dark text-light">

    <div class="container mt-5">

        <h1>DOM XSS</h1>

        <script>

        const hash = location.hash.substring(1);

        document.write(hash);

        </script>

    </div>

    </body>
    </html>
    """


# -----------------------------
# Run App
# -----------------------------

app.run(
    debug=True
)