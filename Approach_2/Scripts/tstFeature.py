import pandas as pd

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
