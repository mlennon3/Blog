import webapp2
import cgi

form = """
<form method="post">
 <textarea name="text" cols=50 rows=10>%(text)s</textarea>
    <div style="color: red">%(error)s</div>
    <br>
    <br>

    <input type="submit">
</form>
"""

class MainPage(webapp2.RequestHandler):
    def write_form(self, error="", text=""):
        self.response.out.write(form % {"error": error,
                                        "text": text})

    def get(self):
        self.write_form()

    def post(self):
        user_text = self.request.get('text')
        escaped_response = escape_html(rot13(user_text))

        self.write_form("", escaped_response)

def rot13(text):
    lowers = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    uppers = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    result = ""
    for c in text:
        if c in lowers:
            index = lowers.index(c)+13
            if index > 25:
                index -= 26
            result += lowers[index]
        elif c in uppers:
            index = uppers.index(c)+13
            if index > 25:
                index -= 26
            result += uppers[index]
        else:
            result += c
    return result

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


app = webapp2.WSGIApplication([('/', MainPage)],
                             debug=True)


