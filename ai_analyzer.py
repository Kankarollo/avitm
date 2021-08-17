from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import logging
from sklearn.preprocessing import StandardScaler
log = logging.getLogger("mylog")

class AIanalyzer():

    def __init__(self):
        pass

    def load_model(self, filename):
        log.info(f"Loading model from: {filename}")
        try:
            self.loaded_rf = joblib.load(filename)
        except Exception as e:
            log.error(f"Loading model failed: {e}")
            raise BlockingIOError(f"Loading model from {filename} failed")

    def analyze_session(self, prepared_data):
        sc = StandardScaler()
        prepared_data = sc.fit_transform(prepared_data)

        return self.loaded_rf.predict(prepared_data)