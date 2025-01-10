# AWS_SecureScan

AWS_SecureScan is a security automation diagnostic tool based on the Cloud Security Guide distributed by SK Shieldus.
## Features

This tool helps automate and streamline AWS security diagnostics by following established security guidelines.
## Getting Started
### Prerequisites

    Create a dedicated diagnostic user in AWS IAM
        Assign the AdministratorAccess policy to the user.
    Update credentials in aws_credentials.json
        Replace the values for access_key, secret_key, and region_name with the key values of the diagnostic user.
    Exclude the diagnostic user from results
        Update the diagnostic_user field in aws_credentials.json to exclude the diagnostic account from the results.

## Development Environment

    Python Version: 3.12.8

## Required Libraries Installation

    pip install requirements.txt

## How to Use

    Clone this repository and navigate to the project directory.
    Set up the AWS IAM user and update aws_credentials.json with the appropriate values.
    Run the script to begin diagnostics.

    python automation.py

## Note

This tool is based on the SK Shieldus Cloud Security Guide and is designed for use in environments that comply with these recommendations.
