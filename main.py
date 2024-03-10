import os
import sqlite3
import uuid
from datetime import timedelta

import markdown
import mdtex2html
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from hugchat import hugchat
from hugchat.login import Login
from werkzeug.security import check_password_hash, generate_password_hash

#----* Logging in and account generation *----#

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/auth'
login_manager.remember_cookie_duration = timedelta(days=7)


# SQLite databases
conn = sqlite3.connect('users.db')
cur = conn.cursor()
cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS tests (
        UserID TEXT,
        tests TEXT
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS startPrompts (
        UserID TEXT,
        startPrompt TEXT
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS history (
        UserID TEXT,
        history TEXT
    )
''')

conn.commit()
conn.close()
class User(UserMixin):
    pass
  
@login_manager.user_loader
def user_loader(username):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()
    if user is None:
        return None
    user = User()
    user.id = username
    return user

@app.before_request
def before_request():
    # Redirect to login if the user is not logged in and trying to access a protected page
    if not current_user.is_authenticated and request.endpoint in ['protected', 'logout']:
        return redirect(url_for('auth'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE username = ?', (username,))
    existing_user = cur.fetchone()
    if existing_user:
        flash('Username already exists')
        conn.close()
        return redirect(url_for('signup'))
    hashed_password = generate_password_hash(password)
    cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()
    flash('Registration successful. You can now log in.')
    return redirect(url_for('login'))
  
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()
    if user is None or not check_password_hash(user[0], password):
        flash('Invalid username or password')
        return redirect(url_for('login'))
    user = User()
    user.id = username
    login_user(user, remember=True)
    flash('Login successful')
    return redirect(url_for('protected'))

@app.route('/protected')
@login_required
def protected():
    message = 'Logged in as: ' + current_user.id
    return render_template('message.html', message=message)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out')
    return 'Logged out'

@app.route('/auth', methods=['GET', 'POST'])
def auth():
  return render_template('auth.html')

#----* Chatting with Professor Grade *----#

# Log in to huggingface and grant authorization to huggingchat
sign = Login()
cookies = sign.login()

# Save cookies to the local directory
cookie_path_dir = "./cookies_snapshot"
sign.saveCookiesToDir(cookie_path_dir)

# Create a ChatBot
chatbot = hugchat.ChatBot(cookies=cookies.get_dict()) 
# or cookie_path="usercookies/<email>.json"

start = "Act as a friendly but strict Tardigrade who is called Professor Grade. You are a teacher who loves helping his students. Your answers are concice and entertaining, whilst still being pedagogical. You also encourage your students to figure out some things on their own, yet you will first have given some answers. When explaining complex topics you do it iin steps with clear subtitles, you also add important terms in an appendix. You will be sure to give some interesting examples as well. You also will not answer any questions that are not related to school subjects such as science, mathematics, english, social studies, language etc.\n\n\n"

history = []
personal_history = {}

@app.route('/')
def index():
  return render_template('home.html')

@app.route('/sendPrompt', methods=['GET', 'POST'])
def sendPrompt():
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('SELECT startPrompt FROM startPrompts WHERE userID = ?', (current_user.id,))
    try:
        startPrompt = cur.fetchone()[0]
    except TypeError:
        startPrompt = start

    conn.commit()
    conn.close()

    query = request.form['text']
    response = ""
    for resp in chatbot.query(
        text=startPrompt+query,
        stream=True
    ):
        try: 
            token = resp['token']
            response += token
        except TypeError:
            continue
    response = markdown.markdown(response)
    user_id = str(current_user.id)
    if user_id not in personal_history:
        personal_history[user_id] = []
    personal_history[user_id].append((query, response))
    return redirect('chat')

@app.route('/chat')
@login_required
def chat():
    user_id = str(current_user.id)
    try:
      return render_template('chat.html', history=personal_history[user_id])
    except KeyError:
      return render_template('chat.html')

@app.route('/clearH', methods=['POST'])
def clearH():
  user_id = str(current_user.id)
  personal_history[user_id] = []
  return redirect('chat')

@login_required
@app.route('/essay', methods=['POST', 'GET'])
def essay():
    userID = current_user.id
    topic = request.form['text']
    n_questions = request.form['n_questions']
    grade = request.form['grade']
  
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    try:
      cur.execute(
      'SELECT startPrompt FROM startPrompts WHERE userID = ?', (userID,))
      startPrompt = cur.fetchone()[0]
    except TypeError:
      startPrompt = start
      
    # save
    conn.commit()
    conn.close()
  
    essayPrompt = f"""
    
    Tell me {n_questions} question to write an essay about. It should be with this topic: {topic}. The level of the essay should be that of a person in grade {grade}. The questions should be very short but be quite open whilst still concrete. Only respond with the question, do NOT explain why you chose the question.
    """
  
    prompt = startPrompt + essayPrompt
  
    response = ""
    for resp in chatbot.query(
        text=prompt,
        stream=True
    ):
      try:
        token = resp['token']
        response += token
      except TypeError:
        continue
    return render_template('essay.html', question=response)

@app.route('/essaySubmit', methods=['POST'])
def essaySubmit():
  print("Has activated function")
  userID = current_user.id
  essay = request.form['textarea']
  print("Essay:" + essay)

  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  try:
    cur.execute(
      'SELECT startPrompt FROM startPrompts WHERE userID = ?', (userID,))
    startPrompt = cur.fetchone()[0]
  except TypeError:
    startPrompt = start
  
  # save
  conn.commit()
  conn.close()

  gradePrompt = f"""Please correct this essay: \"{essay}\". Remember to be encouraging but strict. Divide your resonse into clear paragraphs. Do NOT write the essay back to the user, give general feedback and provide specific examples from the essay. Also be clear in what is incorrect and add proper explanations in the appendix.
  """

  prompt = startPrompt + gradePrompt

  response = ""
  for resp in chatbot.query(
      text=prompt,
      stream=True
  ):
    try:
      token = resp['token']
      response += token
    except TypeError:
      continue
  response = markdown.markdown(response)
  history = [(essay, response)]
  if userID not in personal_history:
    personal_history[userID] = []
  personal_history[userID].append(history[0])
  return render_template('chat.html', history=history)

@app.route('/test', methods=['POST'])
def test():
  userID = current_user.id
  topic = request.form['text']
  n_questions = request.form['n_questions']
  grade = request.form['grade']

  test_prompt = f"""Act as a friendly but strict Tardigrade who is called Professor Grade.You are a teacher who loves helping his students. You are concice and entertaining, whilst still being pedagogical.

Write an exam about {topic}. The exam will feature approximately {n_questions} questions and they will scale up in difficulty. The difficulty is that of a {topic} test for people in grade {grade}.
You will try NOT to write multible choice questions.

Do not talk much in between questions and write the number of each question, going from 1 to {n_questions}.
Be sure to list every question at once, do not tell me one at a time.
"""

  response = ""
  for resp in chatbot.query(
      text=test_prompt,
      stream=True
  ):
    try:
      token = resp['token']
      response += token
    except TypeError:
      continue

  response = mdtex2html.convert(response)

  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  cur.execute(
  'INSERT INTO tests (UserID, tests) VALUES (?, ?);', (userID, response))

  # save
  conn.commit()
  conn.close()

  fake_query = "Generating test..."

  fake_history = [(fake_query, response)]

  if userID not in personal_history:
    personal_history[userID] = []
  personal_history[userID].append(fake_history[0])

  return render_template('test.html', history=fake_history)

@app.route('/testGen')
@login_required
def testGen():
  return render_template('testGen.html')

@app.route('/testHistory')
@login_required
def testHistory():
  userID = current_user.id
  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  cur.execute(
  'SELECT tests FROM tests WHERE UserID == ?', (userID,))
  tests = cur.fetchall()

  # save
  conn.commit()
  conn.close()

  return render_template('testHistory.html', tests=tests)


#----* Personalizing Professor Grade based on feedback *----#

@app.route('/personalize', methods=['GET', 'POST'])
@login_required
def personalize():
  if request.method == 'GET':
    return render_template('personalize.html')
  feedback = request.form['feedback']
  assessment = request.form['assessment']
  if assessment:
    assessment = f"The student got this feedback in response to this: {assessment}"

  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  cur.execute('SELECT startPrompt FROM startPrompts WHERE userID = ?', (current_user.id,))
  startPrompt = cur.fetchone()

  conn.commit()
  conn.close()

  if not startPrompt:
    startPrompt = "Act as a friendly but strict Tardigrade who is called Professor Grade. You are a teacher who loves helping his students. Your answers are concice and entertaining, whilst still being pedagogical. You also encourage your students to figure out some things on their own, yet you will first have given some answers. When explaining complex topics you do it iin steps with clear subtitles, you also add important terms in an appendix. You will be sure to give some interesting examples as well. You also will not answer any questions that are not related to school subjects such as science, mathematics, english, social studies, language etc.\n\n\n"
  
  generation_prompt = f"""A student has gotten this feedback: {feedback}. {assessment}

This prompt is given to define a LLM:

"{startPrompt}"

I want you to change the prompt that will define a LLM so that it encorparates the feedback: "{feedback}. {assessment}". You will NOT respond to the feedback, you will only change the prompt that defines a LLM so that it always will think about the users feedback when giving responses. Only answer with the changed prompt. Do NOT say anything like "Sure, here's a revised prompt that incorporates the feedback".
  
  """

  response = ""
  for resp in chatbot.query(
      text=generation_prompt,
      stream=True
  ):
    try: # continue when token is a None character
      token = resp['token']
      response += token
    except TypeError:
      continue
  
  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  cur.execute('DELETE FROM startPrompts WHERE userID = ?', (current_user.id,))

  cur.execute('INSERT INTO startPrompts (UserID, startPrompt) VALUES (?, ?)', (current_user.id, response,))

  conn.commit()
  conn.close()
  
  start = response

  message = "I have taken your feedback into account. I will help you improve based on it!!!"
  return render_template('message.html', message=message)

@app.route('/clearP', methods=['POST'])
def clearP():
  conn = sqlite3.connect('users.db')
  cur = conn.cursor()

  cur.execute('DELETE FROM startPrompts WHERE userID = ?', (current_user.id,))

  conn.commit()
  conn.close()

  message = "I have forgotten your old feedback, lets focus on new things!!!"
  return render_template('message.html', message=message)

app.run(host='0.0.0.0', port=81)
