import webapp2
import jinja2
import re
import os
import random
import hashlib
import string
import logging
from types import *
from google.appengine.api import memcache
from google.appengine.ext import db
from webapp2_extras.routes import RedirectRoute

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

    def get_wiki(self, pagename):
        wiki_key = db.GqlQuery("SELECT __key__ FROM Wiki "
                            "WHERE pagename=:1 "
                            "ORDER BY created ASC ", pagename)
        
        wiki = Wiki.get(wiki_key)
        if wiki == []:
            return None
        return wiki

    def get_user_id(self, user_id_cookie):
        return user_id_cookie.split('|')[0]

    def check_valid_user_cookie(self, user_id_cookie):
        user_id = self.get_user_id(user_id_cookie)
        if user_id_cookie == self.make_secure_val(user_id):
            return True
        else:
            return False

    def get_user(self):
        user_id_cookie = self.request.cookies.get('user_id', '')
        if user_id_cookie == '':
            return None
        else:
            if self.check_valid_user_cookie(user_id_cookie) == True:
                user = User.get_by_id(int(self.get_user_id(user_id_cookie)))
                return user
            else:
                return None


class WikiPage(Handler):
    def get(self, pagename):
        v = self.request.get('v')
        user = self.get_user()
        if user:
            username = user.username
        else:
            username = ''
        pagename = pagename.split('wiki')[1]
        wiki = self.get_wiki(pagename)
        if not wiki:
            self.redirect('/wiki/_edit%s' %pagename)
        else:
            if v.isdigit():
                if int(v) > len(wiki):
                    wiki = wiki[-1]
                else:
                    wiki = wiki[int(v)-1]
                
            else:
                wiki = wiki[-1]
        self.render('wiki-page.html', wiki = wiki, username = username)

class EditPage(Handler):
    def get(self, pagename):
        #pagename = pagename.split('wiki')[1]
        wiki = self.get_wiki(pagename)
        if not wiki:
            content = 'Start a new page! Add some information here.'
        else:
            wiki = wiki[-1]
            content = wiki.content
        user = self.get_user()
        if user:
            username = user.username
        else:
            username = ''
            self.redirect('/signup')
        self.render('edit.html', username = username, content = content)

    def post(self, pagename):
        #pagename = pagename.split('wiki')[1]
        user = self.get_user()
        if not user:
            self.redirect('/wiki/')
        content = self.request.get("content")
        if not content:
            content = 'This page is blank, why not edit it?'
            version = 1
        else:
            w = self.get_wiki(pagename)
            if w:
                version = 1 + len(self.get_wiki(pagename))
            else:
                version = 1
        wiki = Wiki(content = content, pagename = pagename, version = version)
        wiki.put()
        self.redirect('/wiki%s' %wiki.pagename)





class Wiki(db.Model):
    content = db.TextProperty(required = True)
    pagename = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    version = db.IntegerProperty()

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class HistoryPage(Handler):
    def get(self, pagename):
        wikis = self.get_wiki(pagename)
        if not wikis:
            self.redirect('/wiki/_edit%s' %pagename)
        else:
            reverse_wikis = []
            for wiki in wikis:
                reverse_wikis.insert(0, wiki)
            self.render('history.html', wikis = reverse_wikis)
            

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
        elif self.user_already_exists(username):
            self.write_form(username, email, "That username already exists.")
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
            self.redirect('/wiki/')

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
    def user_already_exists(self, username):
        user_key = db.GqlQuery("SELECT __key__ FROM User "
                            "WHERE username=:1 "
                            "LIMIT 1", username)
        
        user = User.get(user_key)
        logging.error(user)
        if user == []:
            return False
        else:
            return True


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
                self.redirect('/wiki/')
        else:
            self.render('login.html', password_error="Invalid login")

class Logout(Handler):
    def get(self):
        previous_page = os.environ['HTTP_REFERER']
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/wiki/%s' %previous_page)



PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
#route_blog = RedirectRoute('/wiki', )
routes =[('/wiki/signup', UserSignup),
                               ('/wiki/login', Login),
                               ('/wiki/logout', Logout),
                               ('/wiki/_history' + PAGE_RE, HistoryPage),
                               ('/wiki/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ]
#for route in routes:
    #route = RedirectRoute(route[0], handler=route[1], strict_slash=True)

app = webapp2.WSGIApplication(routes=routes,
                              debug=True)