from flask import Flask, request, render_template_string

app = Flask(__name__)

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Training Lab</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        body{
            background:#0d1117;
            color:white;
        }

        .card{
            background:#161b22;
            border:1px solid #30363d;
        }

        a{
            text-decoration:none;
        }
    </style>
</head>

<body>

<div class="container mt-5">

    {{ content|safe }}

</div>

</body>
</html>
"""


@app.route("/")
def home():

    content = """
    <h1 class="mb-4">XSS Training Lab</h1>

    <div class="row">

        <div class="col-md-6">

            <div class="card p-3 mb-3">

                <h4>Reflected XSS Pages</h4>

                <ul>
                    <li><a href="/search">Search</a></li>
                    <li><a href="/login">Login</a></li>
                    <li><a href="/contact">Contact</a></li>
                    <li><a href="/profile?name=test&city=Delhi">Profile</a></li>
<li><a href="/admin?user=admin&role=root&token=12345">Admin Panel</a></li>
                    <li><a href="/settings?theme=dark">Settings</a></li>
                </ul>

            </div>

        </div>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


@app.route("/search")
def search():

    q = request.args.get(
        "q",
        ""
    )

    content = f"""
    <div class="card p-4">

        <h2>Search Page</h2>

        <form>

            <input
                name="q"
                class="form-control mb-3"
                placeholder="Search..."
            >

            <button
                class="btn btn-success"
            >
                Search
            </button>

        </form>

        <hr>

        Results for:
        {q}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    username = ""

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        )

    content = f"""
    <div class="card p-4">

        <h2>Login</h2>

        <form method="POST">

            <input
                name="username"
                class="form-control mb-3"
                placeholder="Username"
            >

            <button
                class="btn btn-primary"
            >
                Login
            </button>

        </form>

        <hr>

        Welcome:
        {username}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


@app.route("/contact", methods=["GET", "POST"])
def contact():

    email = ""
    subject = ""
    message = ""

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        )

        subject = request.form.get(
            "subject",
            ""
        )

        message = request.form.get(
            "message",
            ""
        )

    content = f"""
    <div class="card p-4">

        <h2>Contact Us</h2>

        <form method="POST">

            <input
                name="email"
                class="form-control mb-3"
                placeholder="Email"
            >

            <input
                name="subject"
                class="form-control mb-3"
                placeholder="Subject"
            >

            <textarea
                name="message"
                class="form-control mb-3"
            ></textarea>

            <button
                class="btn btn-warning"
            >
                Send
            </button>

        </form>

        <hr>

        Email:
        {email}

        <br>

        Subject:
        {subject}

        <br>

        Message:
        {message}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():

    name = request.args.get("name", "")
    city = request.args.get("city", "")
    bio = ""

    if request.method == "POST":

        bio = request.form.get(
            "bio",
            ""
        )

    content = f"""
    <div class="card p-4">

        <h2>User Profile</h2>

        <form method="POST">

            <textarea
                name="bio"
                class="form-control mb-3"
                placeholder="Enter bio"
            ></textarea>

            <button
                class="btn btn-info"
            >
                Update Profile
            </button>

        </form>

        <hr>

        Name:
        {name}

        <br>

        City:
        {city}

        <br>

        Bio:
        {bio}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


@app.route("/admin", methods=["GET", "POST"])
def admin():

    user = request.args.get(
        "user",
        ""
    )

    role = request.args.get(
        "role",
        ""
    )

    token = request.args.get(
        "token",
        ""
    )

    notes = ""
    logs = ""

    if request.method == "POST":

        notes = request.form.get(
            "notes",
            ""
        )

        logs = request.form.get(
            "logs",
            ""
        )

    content = f"""
    <div class="card p-4">

        <h2>Admin Dashboard</h2>

        <form method="POST">

            <input
                name="notes"
                class="form-control mb-3"
                placeholder="Notes"
            >

            <input
                name="logs"
                class="form-control mb-3"
                placeholder="Logs"
            >

            <button
                class="btn btn-danger"
            >
                Save
            </button>

        </form>

        <hr>

        User:
        {user}

        <br>

        Role:
        {role}

        <br>

        Token:
        {token}

        <br>

        Notes:
        {notes}

        <br>

        Logs:
        {logs}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )

@app.route("/settings")
def settings():

    theme = request.args.get(
        "theme",
        ""
    )

    content = f"""
    <div class="card p-4">

        <h2>Settings</h2>

        Current Theme:
        {theme}

        <br><br>

        <a href="/">Home</a>

    </div>
    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )