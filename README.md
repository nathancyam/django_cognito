# Readme

## Setup

This project uses pipenv to manage Python dependencies and interpreters

- Install pipenv (https://pipenv.readthedocs.io/en/latest/)

Run the following in the project directory:

```
$> pipenv shell
$> (pipenv-shell) pipenv install
```

From here, you will need to set the following environment variables:

AWS_REGION=ap-southeast-2
AWS_COGNITO_DOMAIN=https://aws_cognito_domain
AWS_COGNITO_CLIENT_ID=client_id
AWS_COGNITO_CLIENT_SECRET=client_secret
AWS_COGNITO_USER_POOL=your_user_pool

## AWS Configuration

Provided that you are starting from scratch, you'll need to create a user-pool, a user-pool client and a domain. When
pipenv installed the dependencies, it should have also pulled in the `aws-cli` library, so you should be able to use
it from the shell, provided that you have activated pipenv.

```
$> (pipenv-shell) aws cli
```