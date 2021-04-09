from flask import Flask
from cs50 import SQL

db = SQL("sqlite:///database.db")

print(db.execute("SELECT * FROM user"))
