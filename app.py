from flask import Flask
from views import views
import joblib  # or you can use pickle
import pickle
import os
app = Flask(__name__)
app.register_blueprint(views, url_prefix="/")
try:
    model_path = os.path.join(os.path.dirname(__file__), 'model', 'XGBoostClassifier.pkl')
    #model= pickle.load(open(model_path, 'rb'))
    model = joblib.load(model_path)
    
    views.model = model
except Exception as e:
    print(f"Failed to load the model. Error: {e}")
    # Handle the exception or exit


if __name__== '__main__':
    app.run(debug=True,port=8000)