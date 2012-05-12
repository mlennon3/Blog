import webapp2
import cgi

form = """
<form method="post" action="/welcome">
    What is your birthday?
    <br>

    <label>
        Month 
            <input type ="text" name="month" value="%(month)s">
    </label>
    <label>
        Day 
        <input type="text" name="day" value="%(day)s">
    </label>
    <label>
        Year 
        <input type="text" name="year" value ="%(year)s">
    </label>
    <div style="color: red">%(error)s</div>
    <br>
    <br>

    
    <input type="submit">
</form>
"""

class MainPage(webapp2.RequestHandler):
    def write_form(self, error="", month="", day="", year=""):
        self.response.out.write(form % {"error": error,
                                        "month": escape_html(month),
                                        "day": escape_html(day),
                                        "year": escape_html(year)})

    def get(self):
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("That doesn't look valid to me", user_month, user_day, user_year)
        else:        
            self.write_form("", user_month, user_day, user_year)


class ThanksHandler(webapp2.RequestHandler):
  def get(self):
    self.response.out.write("Thanks! That's a valid form")




        



def valid_month(month):

    months = ['January',
              'February',
              'March',
              'April',
              'May',
              'June',
              'July',
              'August',
              'September',
              'October',
              'November',
              'December']
          
    if month.capitalize() in months:
        return month.capitalize()


def valid_day(day):
    if type(day) is int and day in range(1, 32):
        return day
    if day.isdigit():
        if int(day) in range(1, 32):
            return int(day)


def valid_year(year):
    if year:
        if year.isdigit() and int(year) in range(1900, 2021):
            return int(year)

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


app = webapp2.WSGIApplication([('/', MainPage), ('/thanks', ThanksHandler)],
                             debug=True)


