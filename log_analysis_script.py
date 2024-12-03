import csv
from collections import defaultdict

# Function to count requests per IP
def count_requests_per_ip(log_file):
    # Create a defaultdict to store the count of requests for each IP
    ip_count = defaultdict(int)
    with open(log_file, 'r') as file:
        # Read each line in the log file
        for line in file:
            # Extract the IP address (first element of the line)
            ip = line.split()[0]
            # Increment the count for this IP address
            ip_count[ip] += 1
    return ip_count

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(log_file):
    # Create a defaultdict to store the count of accesses for each endpoint
    endpoint_count = defaultdict(int)
    with open(log_file, 'r') as file:
        # Read each line in the log file
        for line in file:
            # Extract the endpoint from the line (second part of the HTTP request)
            endpoint = line.split('"')[1].split()[1]
            # Increment the count for this endpoint
            endpoint_count[endpoint] += 1
    # Return the endpoint with the maximum access count
    return max(endpoint_count.items(), key=lambda x: x[1])

# Function to detect suspicious activity
def detect_suspicious_activity(log_file, threshold=10):
    # Create a defaultdict to store the count of failed login attempts per IP
    failed_login_attempts = defaultdict(int)
    with open(log_file, 'r') as file:
        # Read each line in the log file
        for line in file:
            # Check if the line indicates a failed login (HTTP 401 or specific message)
            if '401' in line or 'Invalid credentials' in line:
                # Extract the IP address
                ip = line.split()[0]
                # Increment the failed login attempt count for this IP
                failed_login_attempts[ip] += 1
    # Return a dictionary of IPs with failed login attempts exceeding the threshold
    return {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

# Function to save results to CSV
def save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity):
    # Open a CSV file to write the results
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP section
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_per_ip.items():
            writer.writerow([ip, count])
        
        # Write an empty row for separation
        writer.writerow([])
        # Write Most Accessed Endpoint section
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Write an empty row for separation
        writer.writerow([])
        # Write Suspicious Activity section
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main function to run the analysis
def main():
    # Specify the log file to analyze
    log_file = 'sample.log'
    # Count requests per IP
    requests_per_ip = count_requests_per_ip(log_file)
    # Find the most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(log_file)
    # Detect suspicious activity based on failed login attempts
    suspicious_activity = detect_suspicious_activity(log_file)
    
    # Print the requests count per IP
    print("IP Address           Request Count")
    for ip, count in requests_per_ip.items():
        print(f"{ip:20} {count}")
    
    # Print the most frequently accessed endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # If suspicious activity is detected, print the details
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    
    # Save all results to a CSV file
    save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity)
    print("\nResults saved to log_analysis_results.csv")

# Entry point of the script
if __name__ == "__main__":
    main()