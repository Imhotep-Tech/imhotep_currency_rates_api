from werkzeug.security import check_password_hash
from extensions import db

def security_check(user_id, check_pass):
    password_db = db.execute("SELECT user_password FROM users WHERE user_id = ?", user_id)
    
    if password_db:
        password_db = password_db[0]["user_password"]

    if check_password_hash(password_db, check_pass):
        return True
    else:
        return False

def select_user_data(user_id):
        user_info = db.execute("SELECT user_username, user_mail FROM users WHERE user_id = ?",user_id)

        if user_info:
            user_username = user_info[0]["user_username"]
            user_mail = user_info[0]["user_mail"]
        else:
            user_username = " "
            user_mail = " "

        return user_username, user_mail