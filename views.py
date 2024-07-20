from flask import Blueprint, render_template, request, jsonify
import joblib  # or you can use pickle
import os
import re
import math
from urllib.parse import urlparse

views = Blueprint(__name__,"views")

try:
    model_path = os.path.join(os.path.dirname(__file__), 'model', 'XGBoostCLassifier.pkl')
    #model= pickle.load(open(model_path, 'rb'))
    model = joblib.load(model_path)
    
except Exception as e:
    print(f"Failed to load the model. Error: {e}")


# def shannon_entropy(data):
#     if not data:
#         return 0
#     entropy = 0
#     for x in set(data):
#         p_x = data.count(x) / len(data)
#         entropy += - p_x * math.log2(p_x)
#     return entropy

# # Function to count ldl sequences in a given string
# def count_ldl_sequences(s):
#     return len(re.findall(r'[a-zA-Z]\d[a-zA-Z]', s))

# # Function to count digit sequences in a given string
# def count_digit_sequences(s):
#     return len(re.findall(r'\d+', s))

# # Function to extract features from a URL
# def extract_features(url):
#     parsed_url = urlparse(url)
#     domain = parsed_url.netloc
#     path = parsed_url.path

#     # Tokenize the domain
#     domain_tokens = domain.split('.')
#     domain_token_count = len(domain_tokens)

#     if domain_token_count > 0:
#         avgdomaintokenlen = sum(len(token) for token in domain_tokens) / domain_token_count
#         longdomaintokenlen = max(len(token) for token in domain_tokens)
#     else:
#         avgdomaintokenlen = 0
#         longdomaintokenlen = 0

#     # Count total number of top-level domains
#     tld_count = len(domain_tokens) - 1 if domain_token_count > 1 else 1

#     # Length of the domain
#     domainlength = len(domain)

#     # Length of the directory level in the URL
#     ldl_url = count_ldl_sequences(url)

#     # Length of the path part of the URL (number of letter-digit-letter sequences)
#     ldl_path = count_ldl_sequences(path)

#     # Number of digit sequences in the URL
#     dld_url = count_digit_sequences(url)

#     # Number of digit sequences in the path
#     dld_path = count_digit_sequences(path)

#     domainUrlRatio = domainlength / len(url) if len(url) > 0 else 0

#     NumberofDotsinURL = url.count('.')

#     host_letter_count = sum(c.isalpha() for c in domain)

#     domain_words = re.split(r'\W+', domain)
#     Domain_LongestWordLength = max(len(word) for word in domain_words) if domain_words else 0

#     delimeter_Domain = domain.count('-') + domain.count('_')
#     SymbolCount_Domain = sum(not c.isalnum() for c in domain)

#     Entropy_URL = shannon_entropy(url)
#     file_extension = path.split('.')[-1] if '.' in path else ""
#     Entropy_Extension = shannon_entropy(file_extension)

#     features = [
#         domain_token_count,
#         avgdomaintokenlen,
#         longdomaintokenlen,
#         tld_count,
#         ldl_url,
#         ldl_path,
#         dld_url,
#         dld_path,
#         domainlength,
#         domainUrlRatio,
#         NumberofDotsinURL,
#         host_letter_count,
#         Domain_LongestWordLength,
#         delimeter_Domain,
#         SymbolCount_Domain,
#         Entropy_URL,
#         Entropy_Extension
#     ]

#     return features

# Importing required packages
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests

import dns.resolver  # Make sure to install the dnspython package

# Define feature extraction functions
# 1. Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2. Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except ValueError:
        ip = 0
    return ip

# 3. Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    return 1 if "@" in url else 0

# 4. Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    return 0 if len(url) < 54 else 1

# 5. Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    path = urlparse(url).path.split('/')
    return len([segment for segment in path if segment])

# 6. Checking for redirection '//' in the URL (Redirection)
def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

# 7. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

# 8. Checking for Shortening Services in URL (Tiny_URL)
shortening_services = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"tr\.im|link\.zip\.net"
)

def tinyURL(url):
    return 1 if shortening_services.search(url) else 0

# 9. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# 10. DNS Record Check (DNS_Record)
def dnsRecord(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return 0
    except dns.resolver.NXDOMAIN:
        return 1
    except dns.resolver.NoAnswer:
        return 1
    except dns.resolver.NoNameservers:
        return 1
    except dns.exception.Timeout:
        return 1
    except Exception:
        return 1

# 12. Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url}").read(),
            "xml"
        ).find("REACH")['RANK']
        rank = int(rank)
        return 1 if rank < 100000 else 0
    except (TypeError, urllib.error.URLError):
        return 1

# 13. Survival time of domain: The difference between termination time and creation time (Domain_Age)
# def domainAge(domain_name):
#     creation_date = domain_name.creation_date
#     expiration_date = domain_name.expiration_date
#     if isinstance(creation_date, str) or isinstance(expiration_date, str):
#         try:
#             creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
#             expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
#         except:
#             return 1
#     if not creation_date or not expiration_date:
#         return 1
#     age_of_domain = abs((expiration_date - creation_date).days)
#     return 1 if age_of_domain / 30 < 6 else 0

# # 14. End time of domain: The difference between termination time and current time (Domain_End)
# def domainEnd(domain_name):
#     expiration_date = domain_name.expiration_date
#     if isinstance(expiration_date, str):
#         try:
#             expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
#         except:
#             return 1
#     if not expiration_date:
#         return 1
#     today = datetime.now()
#     end = abs((expiration_date - today).days)
#     return 0 if end / 30 < 6 else 1
from datetime import datetime

# 13. Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date

    if isinstance(creation_date, list):
        creation_date = creation_date[0]  # Take the first element if it's a list

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]  # Take the first element if it's a list

    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        except:
            return 1

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1

    if not creation_date or not expiration_date:
        return 1

    age_of_domain = abs((expiration_date - creation_date).days)
    return 1 if age_of_domain / 30 < 6 else 0

# 14. End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]  # Take the first element if it's a list

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1

    if not expiration_date:
        return 1

    today = datetime.now()
    end = abs((expiration_date - today).days)
    return 0 if end / 30 < 6 else 1


# 15. IFrame Redirection (iFrame)
def iframe(response):
    if not response:
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

# 16. Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if not response:
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

# 17. Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if not response:
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

# 18. Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if not response:
        return 1
    return 0 if len(response.history) <= 2 else 1
def featureExtractions(url):

  features = []
  #Address bar based features (9)
  # features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))


  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  features.append(dns)
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))

  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
#  features.append(label)

  return features



@views.route("/")
def home():
    return render_template("index.html")

@views.route('/predict', methods=['POST'])
def predict():
        # Get the input data from the form
        
        
        # Preprocess the input and make predictions (modify as per your model's requirements)
    data = request.get_json()
    url = data['url']
    #features = extract_features(url)
    features = featureExtractions(url)
    prediction = model.predict([features])
        
        
    result = 'Not Phishing' if prediction == 1 else 'Legitimate'
        
    return jsonify(result=result)
        
        # Create a result message based on the prediction
        #result = 'Phishing' if prediction == 1 else 'Legitimate'
        
        # Render the result on the page
        #return render_template('index.html', url=url, result=result)