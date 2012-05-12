import webapp2
import cgi
import re
form = """
    <form method="post">
    <label>Username
        <input type="text" name="username" value="%(username)s">
    </label>
    <div style="color: red">%(username_error)s</div>
    <br>
    <label>Password
        <input type="password" name="password">
    </label>
    <div style="color: red">%(password_error)s</div>
    <br>
    <label>Verify Password
        <input type="password" name="verify">
    </label>
    <div style="color: red">%(password_match_error)s</div>
    <br>
    <label>Email(optional)
        <input type="text" name="email" value="%(email)s">
    </label>
    <div style="color: red">%(email_error)s</div>
    <input type="submit">
"""

class MainPage(webapp2.RequestHandler):
    def write_form(self, username="", email="", username_error="", password_error="", email_error="", password_match_error=""):
        self.response.out.write(form % {"username": username,
                                        "email": email,
                                        "username_error": username_error,
                                        "password_error": password_error,
                                        "email_error": email_error,
                                        "password_match_error": password_match_error})

    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')


        if not valid_username(username):
            self.write_form(username, email, "That's not a valid username.")
        elif not valid_password(password):
            self.write_form(username, email, "", "That's not a valid password.")
        elif not match_passwords(password, verify):
            self.write_form(username, email, "", "", "", "Your passwords didn't match.")
        elif not valid_email(email):
            self.write_form(username, email, "", "", "That's not a valid email address.")


        else:
            self.redirect('/welcome?username=%s' % username)

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }

def escape_html(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)

USER_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def match_passwords(password, verify):
    if password == verify:
        return True

def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    else:
        return True

class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        self.response.out.write("Welcome, %s!" % username)

app = webapp2.WSGIApplication([('/', MainPage), ('/welcome', Welcome)],
                             debug=True)


