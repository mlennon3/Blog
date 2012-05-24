import os
import webapp2
import jinja2
import re
import cgi
import hashlib
import string
import random
import json
import urllib2
import logging
import time
#from xml import minidom
from google.appengine.api import memcache
from types import *
from google.appengine.ext import db

jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

cache = {} #REMOVE ONCE MEMCACHED REINSTATED

def recent_posts():
    #parts relevant to memcache commented out
    #posts_and_time = memcache.get("posts_and_time")
    #if posts_and_time is not None:
        #return posts_and_time
    try:
        return cache['key']
    except KeyError:
        logging.error("DB HIT")
        posts = db.GqlQuery("SELECT * FROM Post "
                        "ORDER BY created DESC limit 10")
        cache_hit_time = time.time()
        posts_and_time = [posts, cache_hit_time]
        #if not memcache.add("posts_and_time", posts_and_time, 10):
            #logging.error("Memcache set failed.")
        cache['key'] = posts_and_time
        return posts_and_time

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def hash_str(self, s):
        return hashlib.md5(s).hexdigest()

    def make_secure_val(self, s):
        return "%s|%s" %(s, self.hash_str(s + 'secret'))

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self, username, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.md5(username + pw + salt).hexdigest()
        return '%s|%s' %(h, salt)

    def correct_password(self, username, password, entered_password):
        salt = password.split('|')[1]
        pw_check = self.make_pw_hash(username, entered_password, salt)
        return password == pw_check

    def set_user_cookie(self, user_id = ''):
        if user_id != '':
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % str(self.make_secure_val(user_id)), Path = '/')


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content
        return self.render_str("post.html", p = self)


class MainPage(Handler):
    def render_main(self):
        #posts = memcache.get("posts") 
        #COMMENTED OUT FOR MEMCACHE, SHOULD BE RETURNED
        posts = recent_posts()
        cache_hit_time = posts[1]
        self.render('blog-front.html', posts = posts[0], cache_last_hit = round(time.time() - cache_hit_time), post_id = '')

    def get(self):
        self.render_main()

class MainPageJSon(MainPage):
    def get(self):
        list_of_dicts = []
        all_posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC limit 10")

        for post in all_posts:
            list_of_dicts.append({"content": post.content, "subject": post.subject, "created": post.created.strftime("%b %d, %Y")})
        x = json.dumps(list_of_dicts)
        self.response.headers['Content-Type'] = "application/json; charset=utf-8"
        self.response.out.write(x)

        

class SpecificPost(Handler):
    def get(self, post_id):
        s = Post.get_by_id(int(post_id))
        if s:
            post_id = s.key().id()
            self.render("blog-front.html", posts=[s], post_id=str(post_id))
        else:
            self.error(404)
            return

class SpecificPostJSon(Handler):
    def get(self, post_id):
        list_of_dicts = []
        post = Post.get_by_id(int(post_id))
        if post:
            list_of_dicts.append({"content": post.content, "subject": post.subject, "created": post.created.strftime("%b %d, %Y")})
        x = json.dumps(list_of_dicts)
        self.response.headers['Content-Type'] = "application/json; charset=utf-8"
        self.response.out.write(x)

class NewPost(Handler):
    def render_new_post(self, subject="", content="", error=""):
        self.render("new-post.html", subject = subject, content = content, error = error)


    def get(self):
        self.render_new_post()


    def post(self):
        global cache
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = Post(subject = subject, content = content)
            post_key = post.put() #Key('Post', id)
            cache = {} #REMOVE ONCE MEMCACHE IS REINSTATED
            self.redirect('/%d' %post_key.id())
        else:
            error = "need both a title and a post"
            self.render_new_post(subject, content, error)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()


class Cookie(Handler):
    pass


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
            user = User(username = username, password = self.make_pw_hash(username, password), email = email)
            user.put()
            self.set_user_cookie(user_id = '%s' % user.key().id())
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
        user_id_cookie = self.request.cookies.get('user_id', '')
        if user_id_cookie == '':
            self.redirect('/signup')
        else:
            if self.check_valid_cookie(user_id_cookie) == True:
                user = User.get_by_id(int(self.get_user_id(user_id_cookie)))
                self.render('welcome.html', user = user)
            else:
                self.redirect('/signup')

    def get_user_id(self, user_id_cookie):
        return user_id_cookie.split('|')[0]

    def check_valid_cookie(self, user_id_cookie):
        user_id = self.get_user_id(user_id_cookie)
        if user_id_cookie == self.make_secure_val(user_id):
            return True
        else:
            return False
class Login(Handler):
    def get(self):
        self.render('login.html', password_error="")

    def post(self):
        username = self.request.get('username')
        entered_password = self.request.get('password')
        user_c = User.all().filter("username =", (username))
        user = user_c.get()
        if user:
            self.set_user_cookie(user_id = '%s' % user.key().id())
            if not self.correct_password(user.username, user.password, entered_password):
                self.render('login.html', password_error="Invalid login")
            else:
                self.redirect('/welcome')
        else:
            self.render('login.html', password_error="Invalid login")

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')

class FrontJson(Handler):
    def get(self):
        MainPage.get()

app = webapp2.WSGIApplication([('/', MainPage), ('/.json', MainPageJSon),
                                ('/newpost', NewPost), ('/(\d+)', SpecificPost), ('/(\d+).json', SpecificPostJSon), ('/signup', UserSignup), ('/welcome', Welcome), ('/login', Login), ('/logout', Logout),],
                                debug=True)