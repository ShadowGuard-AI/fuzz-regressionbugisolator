import argparse
import logging
import sys
import requests

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
        bool or None: True if the input triggers the bug (the response status is
        outside the success status codes), False if the response status is one
        of the success status codes, and None if the target could not be
        reached at all. None is a distinct third result and is never reported
        as False.
    """
    try:
        params = {parameter: input_value}

        if method == "GET":
            response = requests.get(url, params=params)
        else:  # POST
            response = requests.post(url, data=params)

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed, target could not be reached: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred, target could not be reached: {e}")
        return None

    if response.status_code in success_status_codes:
        return False  # Input did not trigger the bug
    else:
        return True  # Input triggered the bug


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
        tuple: (result, status) where result is a string describing the
        minimal triggering input and the critical character it isolates, or
        None when nothing was isolated. status is 0 when a change was
        isolated, 1 when none was found (including failed preconditions where
        the target answered), and 2 when the target could not be reached.
    """

    logging.info("Starting delta debugging...")

    # Input validation and sanitization:  For demonstration, basic length check
    if len(bug_triggering_input) > 1000 or len(non_triggering_input) > 1000:
        logging.error("Input strings are too long.  Consider shortening.")
        return None, 1

    def triggers(value):
        return test_input(url, parameter, value, method, success_status_codes)

    # Verify the preconditions before claiming anything.
    triggering_result = triggers(bug_triggering_input)
    if triggering_result is None:
        logging.error("Isolation cannot proceed: the target could not be reached.")
        return None, 2
    if triggering_result is not True:
        logging.error("Isolation cannot proceed: the bug-triggering input did not trigger the bug.")
        return None, 1

    non_triggering_result = triggers(non_triggering_input)
    if non_triggering_result is None:
        logging.error("Isolation cannot proceed: the target could not be reached.")
        return None, 2
    if non_triggering_result is not False:
        logging.error("Isolation cannot proceed: the non-triggering input also triggers the bug.")
        return None, 1

    # Real delta debugging (ddmin): shrink the triggering input while it
    # still tests as triggering, trying chunk removals and single chunks at
    # increasing granularity.
    minimal = bug_triggering_input
    n = 2
    while len(minimal) >= 2:
        chunk_size = (len(minimal) + n - 1) // n
        reduced = False

        # Try removing each chunk.
        for start in range(0, len(minimal), chunk_size):
            candidate = minimal[:start] + minimal[start + chunk_size:]
            if candidate and triggers(candidate) is True:
                minimal = candidate
                n = max(n - 1, 2)
                reduced = True
                break
        if reduced:
            continue

        # Try each chunk on its own.
        for start in range(0, len(minimal), chunk_size):
            candidate = minimal[start:start + chunk_size]
            if candidate != minimal and triggers(candidate) is True:
                minimal = candidate
                n = 2
                reduced = True
                break
        if reduced:
            continue

        if n >= len(minimal):
            break
        n = min(n * 2, len(minimal))

    if triggers(minimal) is not True:
        logging.info("Could not isolate the minimal difference.")
        return None, 1

    # Name the critical character: the first character of the minimal input
    # whose removal makes it stop triggering.
    critical = None
    for i in range(len(minimal)):
        candidate = minimal[:i] + minimal[i + 1:]
        if candidate and triggers(candidate) is not True:
            critical = minimal[i]
            break
        if not candidate:
            critical = minimal[i]
            break
    if critical is None and len(minimal) == 1:
        critical = minimal[0]

    logging.info(f"Minimal triggering input: {minimal!r}")
    if critical is not None:
        logging.info(f"Identified a critical character: {critical!r}")
        return f"Minimal triggering input: '{minimal}', critical character: '{critical}'", 0
    return f"Minimal triggering input: '{minimal}'", 0


def load_payloads(payloads_file):
    """
    Loads payloads from a file, one payload per line.
    """
    try:
        with open(payloads_file, 'r') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Payloads file not found: {payloads_file}")
        return None
    except Exception as e:
        logging.error(f"Error reading payloads file: {e}")
        return None


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

    payloads = None
    if args.payloads_file:
        payloads = load_payloads(args.payloads_file)
        if payloads is None:
            print("Could not read the payloads file.")
            sys.exit(2)

    minimal_change, status = delta_debugging(args.url, args.parameter, args.bug_triggering_input, args.non_triggering_input, args.method, success_status_codes)

    if minimal_change:
        print(f"Minimal input change to trigger the bug: {minimal_change}")
    else:
        print("Could not isolate the minimal input change.")

    if payloads is not None:
        print("\nTesting payloads from file:")
        for payload in payloads:
            is_bug_trigger = test_input(args.url, args.parameter, payload, args.method, success_status_codes)
            if is_bug_trigger is None:
                print(f"Payload: {payload} - Triggers Bug: could not be reached")
                status = 2
            else:
                print(f"Payload: {payload} - Triggers Bug: {is_bug_trigger}")

    sys.exit(status)

if __name__ == "__main__":
    main()