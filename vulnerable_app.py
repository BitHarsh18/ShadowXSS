from flask import Flask, request, render_template_string
import html

app = Flask(__name__)


BASE_HTML = """
<!DOCTYPE html>
<html>

<head>

    <title>XSS Training Lab</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

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


# ================================================================
# HOME
# ================================================================

@app.route("/")
def home():

    content = """

    <h1 class="mb-4">
        XSS Training Lab
    </h1>


    <div class="row">

        <div class="col-md-6">

            <div class="card p-3 mb-3">

                <h4>
                    Reflected XSS Pages
                </h4>


                <ul>

                    <li>
                        <a href="/search">
                            Search
                        </a>
                    </li>


                    <li>
                        <a href="/login">
                            Login
                        </a>
                    </li>


                    <li>
                        <a href="/contact">
                            Contact
                        </a>
                    </li>


                    <li>
                        <a href="/profile?name=test&city=Delhi">
                            Profile
                        </a>
                    </li>


                    <li>
                        <a href="/admin?user=admin&role=root&token=12345">
                            Admin Panel
                        </a>
                    </li>


                    <li>
                        <a href="/settings?theme=dark">
                            Settings
                        </a>
                    </li>

                </ul>

            </div>

        </div>

    </div>

    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# SEARCH
# ================================================================

@app.route("/search")
def search():

    q = request.args.get(
        "q",
        ""
    )


    content = f"""

    <div class="card p-4">

        <h2>
            Search Page
        </h2>


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


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# LOGIN
# ================================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    username = ""


    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        )


    content = f"""

    <div class="card p-4">

        <h2>
            Login
        </h2>


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


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# CONTACT
# ================================================================

@app.route(
    "/contact",
    methods=[
        "GET",
        "POST"
    ]
)
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

        <h2>
            Contact Us
        </h2>


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


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# PROFILE
# ================================================================

@app.route(
    "/profile",
    methods=[
        "GET",
        "POST"
    ]
)
def profile():

    name = request.args.get(
        "name",
        ""
    )


    city = request.args.get(
        "city",
        ""
    )


    bio = ""


    if request.method == "POST":

        bio = request.form.get(
            "bio",
            ""
        )


    content = f"""

    <div class="card p-4">

        <h2>
            User Profile
        </h2>


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


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# ADMIN
# ================================================================

@app.route(
    "/admin",
    methods=[
        "GET",
        "POST"
    ]
)
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

        <h2>
            Admin Dashboard
        </h2>


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


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# SETTINGS
# ================================================================

@app.route("/settings")
def settings():

    theme = request.args.get(
        "theme",
        ""
    )


    content = f"""

    <div class="card p-4">

        <h2>
            Settings
        </h2>


        Current Theme:

        {theme}


        <br><br>


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# PHASE 2.1 STEP 3
# CONTROLLED CONTEXT TEST PAGE
# ================================================================

@app.route("/context-test")
def context_test():

    # ------------------------------------------------------------
    # 1. HTML TEXT
    # ------------------------------------------------------------

    html_text = request.args.get(
        "html_text",
        "html_text"
    )


    # ------------------------------------------------------------
    # 2. HTML ATTRIBUTE
    # ------------------------------------------------------------

    attribute = request.args.get(
        "attribute",
        "attribute"
    )


    # ------------------------------------------------------------
    # 3. EVENT HANDLER
    # ------------------------------------------------------------

    event = request.args.get(
        "event",
        "event"
    )


    # ------------------------------------------------------------
    # 4. JAVASCRIPT URL
    # ------------------------------------------------------------

    js_url = request.args.get(
        "js_url",
        "js_url"
    )


    # ------------------------------------------------------------
    # 5. JAVASCRIPT CONTEXT
    # ------------------------------------------------------------

    javascript = request.args.get(
        "javascript",
        "javascript"
    )


    # ------------------------------------------------------------
    # 6. HTML COMMENT
    # ------------------------------------------------------------

    comment = request.args.get(
        "comment",
        "comment"
    )


    # ------------------------------------------------------------
    # Controlled test content
    # ------------------------------------------------------------

    content = f"""

    <div class="card p-4">

        <h2>
            ShadowXSS Context Test
        </h2>


        <!-- =====================================================
             HTML TEXT CONTEXT
             ===================================================== -->

        <h4>
            HTML Text
        </h4>


        <div>

            {html_text}

        </div>


        <hr>


        <!-- =====================================================
             HTML ATTRIBUTE CONTEXT
             ===================================================== -->

        <h4>
            HTML Attribute
        </h4>


        <input
            value="{attribute}"
        >


        <hr>


        <!-- =====================================================
             EVENT HANDLER ATTRIBUTE
             ===================================================== -->

        <h4>
            Event Handler Attribute
        </h4>


        <button
            onclick="{event}"
        >

            Test Event

        </button>


        <hr>


        <!-- =====================================================
             JAVASCRIPT URL ATTRIBUTE
             ===================================================== -->

        <h4>
            JavaScript URL Attribute
        </h4>


        <a
            href="javascript:{js_url}"
        >

            JavaScript Link

        </a>


        <hr>


        <!-- =====================================================
             JAVASCRIPT CONTEXT
             ===================================================== -->

        <h4>
            JavaScript Context
        </h4>


        <script>

            var shadowxss_value = "{javascript}";

        </script>


        <hr>


        <!-- =====================================================
             HTML COMMENT CONTEXT
             ===================================================== -->

        <h4>
            HTML Comment Context
        </h4>


        <!--

            {comment}

        -->


        <br><br>


        <a href="/">
            Home
        </a>

    </div>

    """


    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# SAFE REFLECTION TEST PAGE
# ================================================================

@app.route("/safe")
def safe():

    value = request.args.get(
        "value",
        ""
    )

    # Deliberately HTML-encode user input.
    # This endpoint is the known-safe control for Phase 5 accuracy testing.
    safe_value = html.escape(
        value
    )

    content = f"""

    <div class="card p-4">

        <h2>
            Safe Reflection Page
        </h2>

        <p>
            Reflected Value:
        </p>

        <div>
            {safe_value}
        </div>

        <br><br>

        <a href="/">
            Home
        </a>

    </div>

    """

    return render_template_string(
        BASE_HTML,
        content=content
    )


# ================================================================
# START APPLICATION
# ================================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )