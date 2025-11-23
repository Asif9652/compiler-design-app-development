"""
Train a small RandomForest on synthetic login-attempt-like data and save as model.pkl.
This is intentionally simple — suitable for demo / improving detection over the fallback.
"""

import random, pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def synthetic_sample(is_attack):
    if is_attack:
        patterns = [
            ("admin' OR 1=1 --", "whatever"),
            ("user", " ' UNION SELECT * FROM users -- "),
            ("test", "drop table users;"),
            ("guest", "'; DELETE FROM users; --")
        ]
        u, p = random.choice(patterns)
    else:
        names = ["alice","bob","charlie","deepak","student"]
        u = random.choice(names)
        p = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(6,12)))
    s = (u + " " + p)
    total_len = len(s)
    user_len = len(u)
    pw_len = len(p)
    digits = sum(ch.isdigit() for ch in s)
    special = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
    lower = s.lower()
    has_sql = int(any(kw in lower for kw in ["or 1=1","union select","drop table","select ","insert ","delete ","union"]))
    failed_kw = int(any(w in lower for w in ["fail","failed","wrong","invalid"]))
    return [total_len, user_len, pw_len, digits, special, has_sql, failed_kw]

# create dataset
X = []
y = []
for _ in range(2000):
    X.append(synthetic_sample(False)); y.append(0)
for _ in range(800):
    X.append(synthetic_sample(True)); y.append(1)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

clf = RandomForestClassifier(n_estimators=150, random_state=42)
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
print(classification_report(y_test, pred))

with open("model.pkl", "wb") as fw:
    pickle.dump(clf, fw)
print("Saved model.pkl")
