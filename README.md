# may5 FlaskAI Application Template (with Claude Sonnet 3.5 via AWS Bedrock)

This repository contains the code for the may5 AI application.
This is a site template for the [DevOpser AI Hosting and Development platform](https://app.devopser.io).

## CICD Process (GitOps)

## Development Environment Setup

The easiest way to get up and running is to launch a development environment within the Site Detail page of your site on the [DevOpser platform](https://app.devopser.io). See the following docs for step by step guide:
- [Launch a Development Environment](https://devopser.io/docs/launch-development-environment.html)
    
To launch a Dev environment inside your own infrastructure/ VPC, subscribe to [the Bedrock Flask AMI in AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-tti62q7ulbcoq), spin up an EC2 using the AMI, and clone this repo into the environment. For detailed step by step instructions to get up and running, [please see the following tutorial](https://devopser.io/blog/get-started-building-your-own-ai-application-in-20-minutes.html) or you can use the [Terraform quickstart](https://github.com/DevOpser-io/bedrock-flask-quickstart).

## Deployment Process (Staging and Production)

1. Create a new branch for your changes, or you can use the "dev" branch that has been pre-made for you.
2. Make your changes in the new branch and test your changes thoroughly on a remote dev environment.
3. Create a pull request to the appropriate branch:
   - For staging deployment: Create a pull request to the `staging` branch.
   - For production deployment: Create a pull request to the `main` branch.
4. Wait for the required reviews and checks to pass.
5. Merge your own PR at your discretion. When you merge your PR or push changes to Staging, you will trigger a build and deployment to the staging environment.
6. If everything looks good, merge the PR to main and trigger a build and deployment to the production environment.
