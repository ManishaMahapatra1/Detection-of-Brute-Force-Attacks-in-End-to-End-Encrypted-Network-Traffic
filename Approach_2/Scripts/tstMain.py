import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn.metrics import precision_recall_curve, auc, roc_curve
from sklearn.preprocessing import LabelEncoder
import joblib
import csv
import numpy as np
from sklearn.impute import SimpleImputer

def training_Model():
    print("-----------tM1-----------")
    # Load the network traffic data CSV file
    df = pd.read_csv('network_traffic_data.csv')

    # Select only the relevant columns for feature extraction
    relevant_columns = ['DestinationPort', 'TotalFwdPackets', 'TotalBackwardPackets', 'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FlowDuration']

    # Filter only the rows with the label "Web Attack � Brute Force"
    df = df[df['Label'] == 'Web Attack � Brute Force']

    # Set the time interval t in seconds
    t = 10

    # Extract the relevant features
    df['Number of equally sized response packets'] = df['TotalBackwardPackets'] // t
    df['Number of similarly sized responses'] = df.groupby('TotalLengthofFwdPackets')['TotalBackwardPackets'].transform('count') // t
    df['Number of TCP connections'] = df.groupby('DestinationPort')['DestinationPort'].transform('count') // t
    df['Number of TCP packets'] = df.groupby('DestinationPort')['TotalFwdPackets'].transform('sum') // t
    df['Number of short-living TCP connections'] = df[df['FlowDuration'] < 200].groupby('DestinationPort')['DestinationPort'].transform('count')

    # Select the relevant features for training the classifier
    features = ['Number of equally sized response packets', 'Number of similarly sized responses', 'Number of TCP connections', 'Number of TCP packets', 'Number of short-living TCP connections']
    X = df[features]
    y = df['Label']

    # Split the data into training and testing sets, only if there are instances with the label "Web Attack - Brute Force"
    if df.shape[0] > 0:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Create a SimpleImputer object with strategy='mean'
        imputer = SimpleImputer(strategy='mean')

        # Fit the imputer to the training data
        imputer.fit(X_train)

        # Transform the training data and test data
        X_train = imputer.transform(X_train)
        X_test = imputer.transform(X_test)

        # Train a Random Forest classifier
        clf = RandomForestClassifier()
        clf.fit(X_train, y_train)

        # Save the trained model to a file
        joblib.dump(clf, 'bruteforce_attack_model.joblib')

        # Evaluate the model on the testing set
    accuracy = clf.score(X_test, y_test)
    print(f'Accuracy: {accuracy:.2f}')
    
    print("-----------tM2-----------")

def feature_Extraction():
    print("-----------fE1-----------")
    # Load the network traffic data CSV file
    df = pd.read_csv('network_traffic_data.csv')
    # Select only the relevant columns for feature extraction
    relevant_columns = ['DestinationPort', 'TotalFwdPackets', 'TotalBackwardPackets', 'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FlowDuration']
    # Filter only the rows with the label "Web Attack � Brute Force"
    df = df[df['Label'] == 'Web Attack � Brute Force']
    # Set the time interval t in seconds
    t = 10

    # Extract the relevant features
    df['Number of equally sized response packets'] = df['TotalBackwardPackets'] // t
    df['Number of similarly sized responses'] = df.groupby('TotalLengthofFwdPackets')['TotalBackwardPackets'].transform('count') // t
    df['Number of TCP connections'] = df.groupby('DestinationPort')['DestinationPort'].transform('count') // t
    df['Number of TCP packets'] = df.groupby('DestinationPort')['TotalFwdPackets'].transform('sum') // t
    df['Number of short-living TCP connections'] = df[df['FlowDuration'] < 200].groupby('DestinationPort')['DestinationPort'].transform('count')
    # Select the relevant features for training the classifier
    features = ['Number of equally sized response packets', 'Number of similarly sized responses', 'Number of TCP connections', 'Number of TCP packets', 'Number of short-living TCP connections']
    # Save the relevant features to a new CSV file for training the classifier
    df[features].to_csv('bruteforce_attack_features.csv', index=False)
    print("-----------fE2-----------")

def testing_Model():
    # Load the model
    model = joblib.load('bruteforce_attack_model.joblib')

    # Load the dataset
    data = pd.read_csv('network_traffic_data.csv')

    # Filter only the rows with the label "Web Attack – Brute Force"
    #print("Number of rows before filtering:", len(data))
    data = data[data['Label'] == 'Web Attack � Brute Force']
    #print("Number of rows after filtering:", len(data))


    # Set the time interval t in seconds
    t = 10

    # Extract the relevant features
    data['Number of equally sized response packets'] = data['TotalBackwardPackets'] // t
    data['Number of similarly sized responses'] = data.groupby('TotalLengthofFwdPackets')['TotalBackwardPackets'].transform('count') // t
    data['Number of TCP connections'] = data.groupby('DestinationPort')['DestinationPort'].transform('count') // t
    data['Number of TCP packets'] = data.groupby('DestinationPort')['TotalFwdPackets'].transform('sum') // t
    data['Number of short-living TCP connections'] = data[data['FlowDuration'] < 200].groupby('DestinationPort')['DestinationPort'].transform('count')

    # Select the relevant features for training the classifier
    features = ['Number of equally sized response packets', 'Number of similarly sized responses', 'Number of TCP connections', 'Number of TCP packets', 'Number of short-living TCP connections']

    # Select only the relevant columns for prediction
    X = data[features]

    # Make predictions
    print("Prediction for Brute-force attack starting")
    le = LabelEncoder()
    X_cleaned = remove_nan_inf(X)
    y_pred = le.fit_transform(model.predict(X_cleaned))
    y_true = np.ones(len(X_cleaned))
    print("Prediction for Brute-force attack completed")
    print(y_true.shape)
    print(y_pred.shape)


    # Calculate precision-recall curve and area under the curve
    print("Computing precision-recall curve and area under the curve")
    precision, recall, _ = precision_recall_curve(y_true, y_pred)
    auc = metrics.auc(recall, precision)


    # Calculate ROC curve and area under the curve
    print("Computing ROC curve and area under the curve")
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    auc_roc = metrics.auc(fpr, tpr)

    # Plot the precision-recall curve
    plt.plot(recall, precision, color='b', label=f'PR Curve (AUC={auc:.2f})')

    # Plot the ROC curve
    plt.plot(fpr, tpr, color='r', label=f'ROC Curve (AUC={auc_roc:.2f})')

    plt.xlabel('Recall / False Positive Rate')
    plt.ylabel('Precision / True Positive Rate')
    plt.legend()
    plt.show()

def remove_nan_inf(X):
    X = X.values if isinstance(X, pd.DataFrame) else X
    mask = np.isnan(X).any(axis=1) | np.isinf(X).any(axis=1)
    X_cleaned = X[~mask]
    return X_cleaned

def conversion():
    capture = pyshark.FileCapture('smallfile.pcap', only_summaries=True)

    # Open the CSV file
    with open("network_traffic_dat.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Time", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Length", "Info", "Flags", "Checksum"])

        for packet in capture:
            try:
                time = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                src_ip = packet.ip.src
                src_port = packet[packet.transport_layer].srcport
                dst_ip = packet.ip.dst
                dst_port = packet[packet.transport_layer].dstport
                protocol = packet.transport_layer
                length = packet.length
                info = packet.info
                flags = packet.tcp.flags
                checksum = packet[packet.transport_layer].checksum

            # Write a row to the CSV file
                writer.writerow([time, src_ip, src_port, dst_ip, dst_port, protocol, length, info, flags, checksum])
            except:
                pass

    # Close the PCAP file
    csvfile.close()
    capture.close()


def main():
    # conversion()
    print("-----------First-----------")
    feature_Extraction()
    print("-----------Second-----------")
    training_Model()
    print("-----------Third-----------")
    testing_Model()

main()