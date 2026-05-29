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
                    <li><a href="/profile?name=test">Profile</a></li>
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

    message = ""

    if request.method == "POST":

        message = request.form.get(
            "message",
            ""
        )

    content = f"""
    <div class="card p-4">

        <h2>Contact Us</h2>

        <form method="POST">

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


@app.route("/profile")
def profile():

    name = request.args.get(
        "name",
        ""
    )

    content = f"""
    <div class="card p-4">

        <h2>User Profile</h2>

        Welcome:
        {name}

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