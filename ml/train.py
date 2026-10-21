import joblib

from sklearn.ensemble import IsolationForest


# Feature format:
#
# [resource_type,
#  change_type,
#  port,
#  public_access]
#
# Resource types:
# 1 = S3
# 2 = EC2
#
# Change types:
# 0 = none
# 1 = configuration
# 2 = security
# 3 = tag


training_data = [

    # Normal S3
    [1, 1, 0, 0],
    [1, 1, 0, 0],
    [1, 0, 0, 0],

    # Normal EC2
    [2, 1, 0, 0],
    [2, 3, 0, 0],
    [2, 1, 0, 0],

    # Unusual S3 configuration
    [1, 2, 0, 1]
]


model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)


model.fit(training_data)


joblib.dump(
    model,
    "model.pkl"
)


print(
    "CloudGuard ML model trained successfully."
)

print(
    "Saved as model.pkl"
)
