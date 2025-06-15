# fuzz-RegressionBugIsolator
Identifies the minimal input change required to trigger a regression bug, using a delta debugging approach. Takes two inputs: one that triggers the bug and one that doesn't. - Focused on Simplifies the process of generating and executing fuzzing payloads against web applications. Focuses on parameter manipulation and injection techniques to identify vulnerabilities such as SQL injection or XSS. Allows for quick iteration and vulnerability confirmation.

## Install
`git clone https://github.com/ShadowStrikeHQ/fuzz-regressionbugisolator`

## Usage
`./fuzz-regressionbugisolator [params]`

## Parameters
- `-h`: Show help message and exit
- `--bug_triggering_input`: The input that triggers the regression bug.
- `--non_triggering_input`: The input that does not trigger the regression bug.
- `--url`: The URL to test against.
- `--parameter`: The parameter to fuzz.
- `--method`: No description provided
- `--payloads_file`: No description provided
- `--success_status_codes`: Comma-separated list of HTTP status codes considered as success. Defaults to 200.

## License
Copyright (c) ShadowStrikeHQ
