import pandas as pd
import joblib
from sklearn import metrics
from sklearn.metrics import precision_recall_curve, auc, roc_curve
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
import numpy as np
from sklearn.impute import SimpleImputer

# Define the function to remove NaN and Inf values
def remove_nan_inf(X):
    mask = np.isfinite(X).any(axis=1)
    X_cleaned = X[mask]
    return X_cleaned

# Load the model
model = joblib.load('bruteforce_attack_model.joblib')

# Load the training and testing datasets
train_data = pd.read_csv('network_traffic_data.csv')
test_data = pd.read_csv('data_1aa.csv')

# Filter only the rows with the label "Web Attack – Brute Force" in the training data
train_data = train_data[train_data['Label'] == 'Web Attack � Brute Force']

# Set the time interval t in seconds
t = 10

# Combine the feature engineering steps for the training and testing data
for data in [train_data, test_data]:
    data['Number of equally sized response packets'] = data['TotalBackwardPackets'] // t
    data['Number of similarly sized responses'] = data.groupby('TotalLengthofFwdPackets')['TotalBackwardPackets'].transform('count') // t
    data['Number of TCP connections'] = data.groupby('DestinationPort')['DestinationPort'].transform('count') // t
    data['Number of TCP packets'] = data.groupby('DestinationPort')['TotalFwdPackets'].transform('sum') // t
    data['Number of short-living TCP connections'] = data[data['FlowDuration'] < 200].groupby('DestinationPort')['DestinationPort'].transform('count')

# Select the relevant features for training the classifier
features = ['Number of equally sized response packets', 'Number of similarly sized responses', 'Number of TCP connections', 'Number of TCP packets', 'Number of short-living TCP connections']

# Select only the relevant columns for training
X_train = train_data[features].values
y_train = np.ones(len(X_train))

# Select the relevant features for testing
X_test = test_data[features].values

# Create a SimpleImputer object with strategy='mean'
imputer = SimpleImputer(strategy='mean')

# Fit the imputer to the training data
imputer.fit(X_train)

# Transform the training data and test data
X_test = imputer.transform(X_test)
X_train = imputer.transform(X_train)

model.fit(X_train, y_train)

# Make predictions
print("Prediction for Brute-force attack starting")
le = LabelEncoder()
y_pred = le.fit_transform(model.predict(X_train))
y_true = np.ones(len(X_test))
print("Prediction for Brute-force attack completed")

# Adjust y_pred to have the same size as y_true
if len(y_pred) > len(y_true):
    y_pred = y_pred[:len(y_true)]
elif len(y_pred) < len(y_true):
    y_pred = np.pad(y_pred, (0, len(y_true)-len(y_pred)), 'constant', constant_values=(0))

# Calculate precision-recall curve and area under the curve
print("Computing precision-recall curve and area under the curve")
precision, recall, _ = precision_recall_curve(y_true, y_pred)
auc = metrics.auc(recall, precision)

# Calculate ROC curve and area under the curve
print("Computing ROC curve and area under the curve")
fpr, tpr, _ = roc_curve(y_true, y_pred)
fpr = np.nan_to_num(fpr)
auc_roc = metrics.auc(fpr, tpr)

# Plot the precision-recall curve
plt.plot(recall, precision, color='b', label=f'PR Curve (AUC={auc:.2f})')

# Plot the ROC curve
plt.plot(fpr, tpr, color='r', label=f'ROC Curve (AUC={auc_roc:.2f})')

plt.xlabel('Recall / False Positive Rate')
plt.ylabel('Precision / True Positive Rate')
plt.legend()
plt.show()
#--------------------------------------------------------------------------------
# Clean the training and testing data of NaN and Inf values
X_train_cleaned = remove_nan_inf(X_train)
X_test_cleaned = remove_nan_inf(X_test)

# Fit the model on cleaned data
model.fit(X_train_cleaned, y_train)

# Make predictions on cleaned test data
print("Making predictions on cleaned test data")
y_pred_cleaned = le.fit_transform(model.predict(X_test_cleaned))

# Create y_true array with positive and negative samples for cleaned data
y_true_cleaned = np.concatenate([np.ones(len(X_test_cleaned)), np.zeros(len(X_test_cleaned))])

# Adjust y_pred to have the same size as y_true
if len(y_pred_cleaned) > len(y_true_cleaned):
    y_pred_cleaned = y_pred_cleaned[:len(y_true_cleaned)]
elif len(y_pred_cleaned) < len(y_true_cleaned):
    y_pred_cleaned = np.pad(y_pred_cleaned, (0, len(y_true_cleaned)-len(y_pred_cleaned)), 'constant', constant_values=(0))

# Calculate precision-recall curve and area under the curve for cleaned data
print("Computing precision-recall curve and area under the curve for cleaned data")
precision_cleaned, recall_cleaned, _ = precision_recall_curve(y_true_cleaned, y_pred_cleaned)
auc_cleaned = metrics.auc(recall_cleaned, precision_cleaned)

# Calculate ROC curve and area under the curve for cleaned data
print("Computing ROC curve and area under the curve for cleaned data")
fpr_cleaned, tpr_cleaned, _ = roc_curve(y_true_cleaned, y_pred_cleaned)
fpr_cleaned = np.nan_to_num(fpr_cleaned)
auc_roc_cleaned = metrics.auc(fpr_cleaned, tpr_cleaned)

# Plot the precision-recall curve
plt.plot(recall_cleaned, precision_cleaned, color='b', label=f'PR Curve (AUC={auc_cleaned:.2f})')

# Plot the ROC curve
plt.plot(fpr_cleaned, tpr_cleaned, color='r', label=f'ROC Curve (AUC={auc_roc_cleaned:.2f})')

plt.xlabel('Recall_cleaned / False Positive Rate')
plt.ylabel('Precision_cleaned / True Positive Rate')
plt.legend()
plt.show()

