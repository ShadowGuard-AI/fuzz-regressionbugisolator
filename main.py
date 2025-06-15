import argparse
import logging
import sys
import requests
from parameterized import parameterized

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="fuzz-RegressionBugIsolator: Identifies the minimal input change required to trigger a regression bug.")
    parser.add_argument("--bug_triggering_input", type=str, required=True,
                        help="The input that triggers the regression bug.")
    parser.add_argument("--non_triggering_input", type=str, required=True,
                        help="The input that does not trigger the regression bug.")
    parser.add_argument("--url", type=str, required=True,
                        help="The URL to test against.")
    parser.add_argument("--parameter", type=str, required=True,
                        help="The parameter to fuzz.")
    parser.add_argument("--method", type=str, default="GET", choices=["GET", "POST"],
                        help="The HTTP method to use (GET or POST). Defaults to GET.")
    parser.add_argument("--payloads_file", type=str, required=False,
                        help="File containing fuzzing payloads (one per line).")
    parser.add_argument("--success_status_codes", type=str, default="200",
                        help="Comma-separated list of HTTP status codes considered as success. Defaults to 200.")

    return parser.parse_args()


def test_input(url, parameter, input_value, method, success_status_codes):
    """
    Tests a single input value against the target URL.

    Args:
        url (str): The URL to test.
        parameter (str): The parameter to modify.
        input_value (str): The value to use for the parameter.
        method (str): The HTTP method (GET or POST).
        success_status_codes (list): A list of integer status codes considered success.

    Returns:
        bool: True if the input triggers the bug (i.e., returns a non-success status code), False otherwise.
    """
    try:
        params = {parameter: input_value}

        if method == "GET":
            response = requests.get(url, params=params)
        else:  # POST
            response = requests.post(url, data=params)

        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        if response.status_code in success_status_codes:
            return False  # Input did not trigger the bug
        else:
            return True  # Input triggered the bug

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return False # Treat as not triggering, to continue fuzzing.  Important for stability.
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def delta_debugging(url, parameter, bug_triggering_input, non_triggering_input, method, success_status_codes):
    """
    Applies delta debugging to isolate the minimal difference between a bug-triggering and non-triggering input.

    Args:
        url (str): The URL to test against.
        parameter (str): The parameter to fuzz.
        bug_triggering_input (str): An input that triggers the bug.
        non_triggering_input (str): An input that does not trigger the bug.
        method (str): The HTTP method (GET or POST).
        success_status_codes (list): A list of integer status codes considered as success.

    Returns:
        str: The minimal input change that triggers the bug, or None if no such change is found.
    """

    logging.info("Starting delta debugging...")
    
    # Input validation and sanitization:  For demonstration, basic length check
    if len(bug_triggering_input) > 1000 or len(non_triggering_input) > 1000:
        logging.error("Input strings are too long.  Consider shortening.")
        return None

    # Simple delta debugging: character-by-character comparison
    for i in range(min(len(bug_triggering_input), len(non_triggering_input))):
        if bug_triggering_input[i] != non_triggering_input[i]:
            # Test if changing the bug_triggering_input at this position makes it not trigger the bug
            temp_input = bug_triggering_input[:i] + non_triggering_input[i] + bug_triggering_input[i+1:]
            if not test_input(url, parameter, temp_input, method, success_status_codes):
                # This change makes the bug disappear, so the bug is related to the original character in bug_triggering_input
                logging.info(f"Identified a critical character at index {i}: {bug_triggering_input[i]}")
                return f"Change at index {i}: '{bug_triggering_input[i]}' -> '{non_triggering_input[i]}'"


    # If inputs have different lengths and the common part is not triggering the bug, then
    # the extra part of the bug-triggering input could be the reason.
    if len(bug_triggering_input) > len(non_triggering_input):
        extra_part = bug_triggering_input[len(non_triggering_input):]
        logging.info(f"Extra part in bug_triggering_input: {extra_part}")
        if test_input(url, parameter, non_triggering_input, method, success_status_codes):
            logging.info("The extra part of bug_triggering_input is causing the bug.")
            return f"Extra part causing bug: {extra_part}"
    
    logging.info("Could not isolate the minimal difference.")
    return None


def load_payloads(payloads_file):
    """
    Loads payloads from a file, one payload per line.
    """
    try:
        with open(payloads_file, 'r') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Payloads file not found: {payloads_file}")
        return []
    except Exception as e:
        logging.error(f"Error reading payloads file: {e}")
        return []


def main():
    """
    Main function to parse arguments, run fuzzing, and isolate regression bugs.
    """
    args = setup_argparse()

    try:
        # Validate URL format (very basic)
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            raise ValueError("Invalid URL format. Must start with http:// or https://")

        # Convert success status codes to integers
        success_status_codes = [int(code.strip()) for code in args.success_status_codes.split(",")]

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred during argument parsing: {e}")
        sys.exit(1)

    minimal_change = delta_debugging(args.url, args.parameter, args.bug_triggering_input, args.non_triggering_input, args.method, success_status_codes)

    if minimal_change:
        print(f"Minimal input change to trigger the bug: {minimal_change}")
    else:
        print("Could not isolate the minimal input change.")
        
    if args.payloads_file:
        payloads = load_payloads(args.payloads_file)
        print("\nTesting payloads from file:")
        for payload in payloads:
            is_bug_trigger = test_input(args.url, args.parameter, payload, args.method, success_status_codes)
            print(f"Payload: {payload} - Triggers Bug: {is_bug_trigger}")

if __name__ == "__main__":
    main()