import os
import webapp2
import jinja2
import re
import cgi

from google.appengine.ext import db

jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content
        return self.render_str("post.html", p = self)


class MainPage(Handler):
    def render_main(self):
        all_posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC limit 10")



        self.render('blog-front.html', posts = all_posts, post_id = '')



    def get(self):
        self.render_main()


class SpecificPost(Handler):
    def get(self, post_id):
        s = Post.get_by_id(int(post_id))
        if s:
            post_id = s.key().id()
            self.render("blog-front.html", posts=[s], post_id=str(post_id))
        else:
            self.error(404)
            return

class NewPost(Handler):
    def render_new_post(self, subject="", content="", error=""):
        self.render("new-post.html", subject = subject, content = content, error = error)


    def get(self):
        self.render_new_post()


    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = Post(subject = subject, content = content)
            post_key = post.put() #Key('Post', id)

            self.redirect('/%d' %post_key.id())
        else:
            error = "need both a title and a post"
            self.render_new_post(subject, content, error)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()


class UserSignup(Handler):
    def write_form(self, username="", email="", username_error="", password_error="", email_error="", password_match_error=""):

        self.render('user-signup.html', username = username, email= email, 
                                        username_error = username_error,
                                        password_error = password_error,
                                        email_error = email_error,
                                        password_match_error = password_match_error)
    

    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')

        if not self.valid_username(username):
            self.write_form(username, email, "That's not a valid username.")
        elif not self.valid_password(password):
            self.write_form(username, email, "", "That's not a valid password.")
        elif not self.match_passwords(password, verify):
            self.write_form(username, email, "", "", "", "Your passwords didn't match.")
        elif not self.valid_email(email):
            self.write_form(username, email, "", "", "That's not a valid email address.")


        else:
            self.response.headers.add_header('Set-Cookie', str('username=%s' % username))
            user = User(username = username, password = password, email = email)
            self.redirect('/welcome')


    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        return PASSWORD_RE.match(password)

    def match_passwords(self, password, verify):
        if password == verify:
            return True

    def valid_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        if email:
            return EMAIL_RE.match(email)
        else:
            return True


class Welcome(Handler):
    def get(self):
        username = self.request.cookies.get('username', '')
        if username == '':
            self.redirect('/signup')
        self.render('welcome.html', username = username)

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/newpost', NewPost), ('/(\d+)', SpecificPost), ('/signup', UserSignup), ('/welcome', Welcome)],
                                debug=True)