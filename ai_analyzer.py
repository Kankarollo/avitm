from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import logging
import xgboost
from sklearn.preprocessing import StandardScaler
log = logging.getLogger("mylog")

class AIanalyzer():

    def __init__(self):
        pass

    def load_RandomForest_model(self, filename):
        log.info(f"Loading model from: {filename}")
        try:
            self.loaded_rf = joblib.load(filename)
        except Exception as e:
            log.error(f"Loading model failed: {e}")
            raise BlockingIOError(f"Loading model from {filename} failed")

    def load_xgboost_model(self, filename):
        try:
            self.xgboost_model = xgboost.XGBClassifier()
            self.xgboost_model.load_model(filename)
        except Exception as e:
            log.error(f"Loading model failed: {e}")
            raise BlockingIOError(f"Loading model from {filename} failed")

    def analyze_session_RandomForest(self, prepared_data):
        sc = StandardScaler()
        prepared_data = sc.fit_transform(prepared_data)

        return self.loaded_rf.predict(prepared_data)

    def analyze_session_xgboost(self, prepared_data):
        return self.xgboost_model.predict(prepared_data)