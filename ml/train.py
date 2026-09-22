import joblib

from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------
# Feature format
#
# [resource_type,
#  change_type,
#  port,
#  public_access]
# ---------------------------------------------------------

training_data = [

    # Normal S3
    [1, 1, 0, 0],
    [1, 1, 0, 0],
    [1, 0, 0, 0],

    # Normal EC2
    [2, 1, 0, 0],
    [2, 3, 0, 0],
    [2, 1, 0, 0],

    # Normal security group
    [3, 1, 22, 0],
    [3, 1, 3389, 0],

    # Unusual configurations
    [3, 2, 22, 1],
    [3, 2, 3389, 1],
    [1, 2, 0, 1]
]


model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)


model.fit(
    training_data
)


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
