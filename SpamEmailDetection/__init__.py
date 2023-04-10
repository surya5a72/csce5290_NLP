"""
The flask application package.
"""

from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

import SpamEmailDetection.SpamDetection
