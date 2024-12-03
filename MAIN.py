import csv
from collections import defaultdict

# Configuration as per assignment
FAILED_LOGIN_THRESHOLD = 10

#  function to write results to a CSV file
def write_to_csv(data, headers, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(data)

def analyze_log_file(log_file):
    # Data structures for analysis
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_logins = defaultdict(int)

    try:
        with open(log_file, 'r', encoding='utf-8') as file:
            for line in file:
                # Extract IP addresses
                parts = line.split()
                if len(parts) < 9:
                    continue

                ip = parts[0]
                method, endpoint, protocol = parts[5][1:], parts[6], parts[7]
                status_code = parts[8]

                # Count requests
                ip_request_count[ip] += 1

                # Count endpoint access
                endpoint_access_count[endpoint] += 1

                # failed login attempts count
                if status_code == '401':
                    failed_logins[ip] += 1

        # need to Sort data for output
        sorted_ip_requests = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)
        most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1])
        suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

        # for  Display results
        print("Requests per IP Address:")
        print(f"{'IP Address':<20} {'Request Count':<15}")
        for ip, count in sorted_ip_requests:
            print(f"{ip:<20} {count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count:<15}")

        # Save results to CSV file
        write_to_csv(sorted_ip_requests, ["IP Address", "Request Count"], "requests_per_ip.csv")
        write_to_csv([most_accessed_endpoint], ["Endpoint", "Access Count"], "most_accessed_endpoint.csv")
        write_to_csv(suspicious_ips, ["IP Address", "Failed Login Count"], "suspicious_activity.csv")

        print("\nResults have been saved to CSV files.")
    # exception handling
    except FileNotFoundError:
        print(f"Error: The file {log_file} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ")
    #log_file_path = "/Users/pavanpatil/Developer/DSA/testFile.log"
    analyze_log_file(log_file_path)
