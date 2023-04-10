"""
This script runs the SpamEmailDetection application using a development server.
"""

from os import environ
from SpamEmailDetection import app

if __name__ == '__main__':     
  app.run()

app.secret_key = "192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf" 