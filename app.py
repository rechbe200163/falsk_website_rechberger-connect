from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, validators, ValidationError, TextAreaField, SelectField
from wtforms.validators import InputRequired, Email, EqualTo, Length

app = Flask(__name__)
SECRET_KEY = b'\x8f>Mv\nq1w\xcf\x07?2\xed\xdbvG'
app.config['SECRET_KEY'] = SECRET_KEY
#creating database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

#creating table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable = False)
    email = db.Column(db.String(120), unique=True, nullable = False)
    password = db.Column(db.String(80), unique=True, nullable = False)

    def __repr__(self):
        return '<User %r>' % self.username

#creating message table
class Message(db.Model):
		id = db.Column(db.Integer, primary_key=True)
		message = db.Column(db.String(80))

		def __repr__(self):
				return '<Message %r>' % self.message

#creating flask form for message board
class MessageBoard(FlaskForm):
	message = StringField('message', validators=[InputRequired()])
	submit = SubmitField('Submit')
    
#creating flask form for registration
class RegistrationForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=2, max=80)], render_kw={"placeholder": "Username"}, description="Username")
	email = StringField('email', validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"}, description="Email")
	password = PasswordField('password', validators=[InputRequired()], render_kw={"placeholder": "Password"}, description="Password", )
	passwordcheck = PasswordField('passwordcheck', validators=[InputRequired() ,Length(min=8, max=80)], render_kw={"placeholder": "Password"}, description="Password")
	submit = SubmitField('Submit')
  
  #checking if password and passwordcheck are the same
	def validate_passwordcheck(self, passwordcheck):
		if passwordcheck.data != self.password.data:
			raise ValidationError('Passwords do not match')
    
  #cheking if username is already taken
	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user:
				raise ValidationError('Username already taken') 

  #checking if email is already taken
	def validate_email(self, email):
		email = User.query.filter_by(email=email.data).first()
		if email:
			raise ValidationError('Email already taken')


@app.route('/message', methods=['GET', 'POST'])
def message():
	form = MessageBoard()
	if form.validate_on_submit():
		message = form.message.data
		message = Message(message=message)
		db.session.add(message)
		db.session.commit()
		return redirect(url_for('message'))
	messages = list(Message.query.all())
	return render_template('messageboard.html', form=form, Messages=messages)

@app.route('/message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    flash('The message has been deleted.')
    return redirect(url_for('message'))

@app.route('/register' , methods=['GET', 'POST'])
def signin():
    error = None
    form = RegistrationForm()
    if form.validate_on_submit():
      user = User(username=form.username.data, email=form.email.data, password=form.password.data)
      db.session.add(user)
      db.session.commit()
      return redirect(url_for('index'))
    return render_template("register.html", error=error, form=form)

#index route
@app.route('/')
def index():
	return render_template('index.html')

#starting the server
if __name__ == '__main__':
  with app.app_context():
    db.create_all()  
    app.run(debug=True)
