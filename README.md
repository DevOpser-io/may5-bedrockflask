# devopserportal-cicd

Please refer to the obsidian notes regarding [devopser openai demo cicd](https://github.com/DevOpser-io/obsidianvault/blob/main/DevOpser%20OpenAI%20Demo%20CICD.md).

This project is containerizing the OpenAI Python quickstart for chat-basic:
https://github.com/openai/openai-quickstart-python/tree/master

# modifications:
- sticky sessions + redis
- "clear" button
- DevOpser Logo
- Prometheus instrumentation for Groundcover at /metrics
- Use of AWS Secrets Manager at runtime for ENV variables for enhanced security
- healthcheck at /health
