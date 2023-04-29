"""
Routes and views for the flask application.
"""

import sys
import re
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from flask import render_template, jsonify, request, send_file
from datetime import datetime
import os
import urllib.request
from SpamEmailDetection import app
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer


emailpattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
nohttps = r'/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/'
urlpattern = r'^https?://[\w.-]+(?:\.[\w]+)+[\w\-._~:/?#[\]@!$&\'()*+,;=]*$'
nohttpspattern = r'^http://[\w.-]+(?:\.[\w]+)+[\w\-._~:/?#[\]@!$&\'()*+,;=]*$'
httpspattern = r'^https://[\w.-]+(?:\.[\w]+)+[\w\-._~:/?#[\]@!$&\'()*+,;=]*$'
dotpattern = r'\.'
ippattern = r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
dashurlpattern = r'/\(\([a-z_-]*\.[a-z_-]*\)\|\([a-z_]*\.[a-z_-]*\.[a-z_-]*\)\)/'
numpattern = r'[0-9]'
stringpattern = r'[a-zA-z]'
sensitivepattern = r'(.)\1{9,}'
hostnamepattern = r'^https?://([\w.-]+)'
hostpathpattern = r'^https?://[\w.-]+(/.*)'
querypattern = r'(?<=\?)\S+'    # r'^https?://[\w.-]+(/.*)\?(\S+)'
subdomainpattern = r'(?<=://)([\w.-]+)\.'



@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    return render_template(
        'layout.html',
        title='Home Page',
        year=datetime.now().year,
    )

@app.route('/api/spamdetection', methods=['POST'])
def detect_spam():
    try:
        number_of_dots = 0
        number_of_subdomainlevel = 0
        number_of_PathLevel = 0
        number_of_URLLength = 0
        number_of_numDash = 0
        number_of_numDash_Hostname = 0
        number_of_AtSymbol = 0
        number_of_Tildesymbol = 0
        number_of_underScore = 0
        number_of_numPercent = 0
        number_of_numAmpersand = 0
        number_of_numHash = 0
        number_of_numeric_chars = 0
        number_of_Query_Components = 0
        number_of_RandomString = 0
        number_of_IpAddress = 0
        number_of_NoHttps = 0
        number_of_Https = 0
        number_of_DoubleSlash = 0
        number_of_sensitive_words = 0
        number_of_emails = 0
        Hostname_Length = 0
        Path_Length = 0
        Query_Length = 0
        PctNullSelfRedirectHyperlinks = 0

        data = request.get_json()
        to_val = data['to']
        from_val = data['from']
        subject_val = data['subject']
        body_val = data['body']
        # write you code here to create the dataset record.
        input_val = subject_val + ' ' + body_val  # taking input from subject and Body of email.
        input_context = beautify(input_val)
        print(input_context)
        print(input_val)

        # add sentiment analysis
        analyzer = SentimentIntensityAnalyzer()
        sentiment = analyzer.polarity_scores(input_val)
        print("Sentiment Analysis: if the Compund resut is in -, then the sentiment is negative and if there is only 0 then it is positive")
        print(sentiment)

        # determine the sentiment of the input
        if sentiment['compound'] < 0:
            sentiment_result = "Negative"
        elif sentiment['compound'] > 0:
            sentiment_result = "Positive"
        else:
            sentiment_result = "Neutral"

        for key in input_context:
            if apply_regex(key, dotpattern):
                number_of_dots = number_of_dots + input_context[key]
            if apply_regex(key, querypattern):
                number_of_subdomainlevel = number_of_subdomainlevel + len(re.search(subdomainpattern, key).group(1).split('.'))
            number_of_PathLevel = 0
            if apply_regex(key, urlpattern):
                number_of_URLLength = number_of_URLLength + len(key)
            number_of_numDash = number_of_numDash + key.count('-')
            if apply_regex(key, dashurlpattern):
                number_of_numDash_Hostname = key.count('-')
            number_of_AtSymbol = number_of_AtSymbol + key.count('@')
            number_of_Tildesymbol = number_of_Tildesymbol + key.count('~')
            number_of_underScore = number_of_underScore + key.count('_')
            number_of_numPercent = number_of_numPercent + key.count('%')
            number_of_numAmpersand = number_of_numAmpersand + key.count('&')
            number_of_numHash = number_of_numHash + key.count('#')
            if apply_regex(key, numpattern):
                number_of_numeric_chars = number_of_numeric_chars + input_context[key]
            number_of_Query_Components = 0
            if apply_regex(key, stringpattern):
                number_of_RandomString = number_of_RandomString + input_context[key]
            if apply_regex(key, ippattern):
                number_of_IpAddress = input_context[key]
            if apply_regex(key, nohttpspattern):
                number_of_NoHttps = number_of_NoHttps + input_context[key]
            if apply_regex(key, hostnamepattern):
                Hostname_Length = Hostname_Length + len(re.search(hostnamepattern, key).group(1))
            if apply_regex(key, hostpathpattern):
                Path_Length = Path_Length + len(re.search(hostpathpattern, key).group(1))
            if apply_regex(key, querypattern):
                Query_Length = Query_Length + len(re.search(querypattern, key).group())
            if apply_regex(key, httpspattern):
                number_of_Https = number_of_Https + input_context[key]
            number_of_DoubleSlash = number_of_DoubleSlash + key.count('//')
            if apply_regex(key, sensitivepattern):
                number_of_sensitive_words = number_of_sensitive_words + input_context[key]
            if apply_regex(key, emailpattern):
                number_of_emails = number_of_emails + input_context[key]
            if key.count('<script>') > 0:
                PctNullSelfRedirectHyperlinks = 1

        data_values = [[number_of_dots, number_of_subdomainlevel, number_of_PathLevel,
                        number_of_URLLength, number_of_numDash, number_of_numDash_Hostname,
                        number_of_AtSymbol, number_of_Tildesymbol, number_of_underScore,
                        number_of_numPercent, number_of_Query_Components, number_of_numAmpersand,
                        number_of_numHash, number_of_numeric_chars, number_of_NoHttps,
                        number_of_RandomString, number_of_IpAddress, 0, 0, number_of_Https,
                        Hostname_Length, Path_Length, Query_Length, number_of_DoubleSlash,
                        number_of_sensitive_words, 0, 0.909090909, 1, 0, 1,
                        0, 0, 0, 0,
                        PctNullSelfRedirectHyperlinks, 0, 0, 0, 0, 0, 0, 0, 1, -1, 1, 1, 0, 1]]
        print(data_values)
        # data_values = [[2,0,5,60,0,0,0,0,0,0,0,0,0,1,1,0,0,0,1,0,17,36,0,0,0,1,0.909090909,1,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,-1,1,1,0,1]]
        # print(data_values)
        # data_values = [[6, 0, 0, 69, 2, 0, 2, 5, 0, 9, 0, 0, 6, 2, 1, 14, 0, 0, 0, 1, 28, 26, 0, 2, 0, 0, 0,1,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,-1,1,1,0,1]]
        # print(data_values)
        
        path = os.getcwd()
        filepath = path + "/Phishing_Legitimate_full.csv"
        # define header names
        header_names = ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname',
                        'AtSymbol',
                        'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
                        'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress', 'DomainInSubdomains',
                        'DomainInPaths',
                        'HttpsInHostname', 'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
                        'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks', 'PctExtResourceUrls',
                        'ExtFavicon',
                        'InsecureForms', 'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction',
                        'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch', 'FakeLinkInStatusBar',
                        'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
                        'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
                        'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT',
                        'CLASS_LABEL']
        # display table
        # print(data_values)
        dataset = pd.read_csv(filepath, names=header_names)
        dataset.head()
        x = dataset.iloc[:, :-1].values
        y = dataset.iloc[:, 48].values

        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.20)
        classifier = RandomForestClassifier(n_estimators=100)
        classifier.fit(x_train, y_train)
        y_pred = classifier.predict(x_test)
        # print(y_pred)
        result = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(result)
        result1 = classification_report(y_test, y_pred)
        print("Classification Report:", )
        print(result1)
        result2 = accuracy_score(y_test, y_pred)
        print("Accuracy:", result2)

        x_test = data_values
        y_pred = classifier.predict(x_test)
        print(y_pred)
        return jsonify({'data': "Spam Detected" if y_pred[0] == 1 else "Not Spam",  'sentiment_analysis_result':  "Sentiment Analysis for the Data is: " + sentiment_result,})
    except Exception as err:
        return jsonify({'data': err})


def beautify(text):
    import nltk
    nltk.download('stopwords')
    from nltk.corpus import stopwords
    token_list = {}

    tokens = [t for t in text.split()]
    clean_tokens = tokens[:]
    sr = stopwords.words('english')
    for token in tokens:
        if token in stopwords.words('english'):
            clean_tokens.remove(token)

    freq = nltk.FreqDist(clean_tokens)

    for key, val in freq.items():
        token_list[key] = val

    return token_list


def apply_regex(data, pattern):
    if re.findall(pattern, data):
        return True
    elif re.match(pattern, data):
        return True
    elif re.search(pattern, data):
        return True
    else:
        return False



