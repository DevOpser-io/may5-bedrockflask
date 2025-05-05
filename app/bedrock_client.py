import boto3
import json
import logging
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from config import Config

logger = logging.getLogger(__name__)

class BedrockClient:
    def __init__(self, region_name="us-east-1", cross_account_role_arn=None):
        self.region_name = region_name
        self.cross_account_role_arn = cross_account_role_arn
        self.credentials_expiration = None  # To track when temporary credentials expire
        self._initialize_client()

        self.model_id = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
        self.default_system_message = (
            "Write naturally, using formatting only when it genuinely enhances content clarity or readability.\n\n"
            "Document Structure:\n"
            "- Always use headers (# or ##) for titles of articles, essays, or documents\n"
            "- Use subheaders (## or ###) for major sections in longer content\n\n"
            "Technical Content:\n"
            "- Use code blocks only for actual code, commands, or technical output\n"
            "- Use inline code only for variables, commands, or technical terms\n\n"
            "Lists and Emphasis:\n"
            "- Use lists only for sequential steps or truly itemized content\n"
            "- Use bold/italic only for genuine emphasis or standard writing conventions\n\n"
            "Avoid excessive formatting in:\n"
            "- Natural dialogue within stories\n"
            "- Descriptive narrative passages\n"
            "- Informal responses\n"
            "- Conversational exchanges\n\n"
            "Format titles and major sections with headers even in narrative content, but keep the rest of the narrative flowing naturally. When in doubt about other formatting, prefer plain text. Use appropriate Markdown syntax for:\n"
            "- Code blocks (with language specification)\n"
            "- Inline code\n"
            "- Lists (ordered and unordered)\n"
            "- Headers (use appropriate levels)\n"
            "- Bold and italic text\n"
            "- Links\n"
            "- Blockquotes"
        )

    def _initialize_client(self):
        if self.cross_account_role_arn:
            logger.info(f"Assuming cross-account role: {self.cross_account_role_arn}")
            credentials = self.assume_role(self.cross_account_role_arn)
            # Store expiration from the assumed role credentials.
            self.credentials_expiration = credentials["Expiration"]
            self.client = boto3.client(
                service_name='bedrock-runtime',
                region_name=self.region_name,
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"]
            )
        else:
            logger.info("Using default credentials for Bedrock client")
            self.client = boto3.client(
                service_name='bedrock-runtime',
                region_name=self.region_name
            )

    def assume_role(self, role_arn, session_name="BedrockSession"):
        """
        Assumes the given cross-account role and returns temporary credentials.
        """
        try:
            sts_client = boto3.client("sts")
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name
            )
            logger.info("Assumed role successfully")
            return response["Credentials"]
        except ClientError as e:
            logger.error(f"Failed to assume role {role_arn}: {str(e)}")
            raise

    def refresh_credentials_if_needed(self):
        """
        Refresh credentials if they are within 5 minutes of expiration.
        """
        # Use timezone-aware datetime for comparison
        if self.credentials_expiration and datetime.now(timezone.utc) > (self.credentials_expiration - timedelta(minutes=5)):
            logger.info("Refreshing credentials as they are about to expire")
            credentials = self.assume_role(self.cross_account_role_arn)
            self.credentials_expiration = credentials["Expiration"]
            self.client = boto3.client(
                service_name='bedrock-runtime',
                region_name=self.region_name,
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"]
            )

    def _prepare_messages(self, messages):
        """Convert messages to Claude's format"""
        logger.info(f"Input messages before formatting: {json.dumps(messages, indent=2)}")
        
        formatted_messages = []
        system_message = self.default_system_message
        
        # Filter out empty messages
        valid_messages = [msg for msg in messages if msg.get("content")]
        logger.info(f"Valid messages after filtering: {json.dumps(valid_messages, indent=2)}")
        
        for msg in valid_messages:
            role = msg.get("role", "user")
            content = [{"type": "text", "text": msg["content"]}]
            
            if role == "system":
                # Append any additional system messages to our default
                system_message = f"{system_message}\n{msg['content']}"
            elif role in ["user", "assistant"]:
                formatted_messages.append({
                    "role": role,
                    "content": content
                })
            else:
                # Default to 'user' for unrecognized roles
                formatted_messages.append({
                    "role": "user",
                    "content": content
                })
        
        # If no messages, add a default user message
        if not formatted_messages:
            formatted_messages.append({
                "role": "user",
                "content": [{"type": "text", "text": "Hello"}]
            })
        
        logger.info(f"Final formatted messages: {json.dumps(formatted_messages, indent=2)}")
        logger.info(f"Final system message: {system_message}")
        
        return formatted_messages, system_message

    def create_chat_completion(self, messages, stream=True):
        """Create a chat completion with Bedrock"""
        # Refresh credentials if needed
        if self.cross_account_role_arn:
            self.refresh_credentials_if_needed()
            
        try:
            logger.info("Starting chat completion with messages:")
            logger.info(f"Raw input messages: {json.dumps(messages, indent=2)}")
            
            # Prepare messages and get system message
            formatted_messages, system_message = self._prepare_messages(messages)
            
            # Prepare the request body
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": formatted_messages,
                "max_tokens": 4096,
                "temperature": 0.7
            }
            
            # Add system message if present
            if system_message:
                request_body["system"] = [{"type": "text", "text": system_message}]
            
            logger.info(f"Final request body being sent to Bedrock: {json.dumps(request_body, indent=2)}")

            if stream:
                response_stream = self.client.invoke_model_with_response_stream(
                    modelId=self.model_id,
                    body=json.dumps(request_body),
                    contentType="application/json",
                    accept="application/json"
                )
                return self._process_stream(response_stream)
            else:
                response = self.client.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps(request_body),
                    contentType="application/json",
                    accept="application/json"
                )
                return self._process_response(response)

        except ClientError as e:
            # If an ExpiredTokenException is caught, refresh credentials and retry once.
            if "ExpiredTokenException" in str(e):
                logger.warning("Expired token detected during API call; refreshing credentials and retrying.")
                self.refresh_credentials_if_needed()
                if stream:
                    response_stream = self.client.invoke_model_with_response_stream(
                        modelId=self.model_id,
                        body=json.dumps(request_body),
                        contentType="application/json",
                        accept="application/json"
                    )
                    return self._process_stream(response_stream)
                else:
                    response = self.client.invoke_model(
                        modelId=self.model_id,
                        body=json.dumps(request_body),
                        contentType="application/json",
                        accept="application/json"
                    )
                    return self._process_response(response)
            else:
                logger.error(f"Bedrock API error: {str(e)}")
                logger.error(f"Failed request body: {json.dumps(request_body, indent=2)}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error in create_chat_completion: {str(e)}")
            raise

    def _process_stream(self, response_stream):
        """Process streaming response from Bedrock"""
        logger.info("Starting to process response stream")
        
        try:
            for event in response_stream["body"]:
                logger.debug(f"Raw event: {event}")
                if "chunk" in event:
                    chunk_bytes = event["chunk"]["bytes"]
                    chunk_data = json.loads(chunk_bytes)
                    logger.debug(f"Decoded chunk: {json.dumps(chunk_data, indent=2)}")
                    if chunk_data.get("type") == "content_block_delta":
                        text = chunk_data["delta"].get("text", "")
                        if text:
                            logger.debug(f"Yielding content: {text}")
                            yield {
                                "choices": [{
                                    "delta": {"content": text},
                                    "finish_reason": None
                                }]
                            }
                    elif chunk_data.get("type") == "end_of_sequence":
                        logger.info("Received end_of_sequence signal")
                        yield {
                            "choices": [{
                                "delta": {},
                                "finish_reason": "stop"
                            }]
                        }
                elif any(key in event for key in ["internalServerException", "modelStreamErrorException", 
                                                    "validationException", "throttlingException"]):
                    error_type = next(key for key in event.keys() if key in [
                        "internalServerException", "modelStreamErrorException",
                        "validationException", "throttlingException"
                    ])
                    logger.error(f"Stream error: {error_type}")
                    raise Exception(f"Stream error: {error_type}")
        except Exception as e:
            logger.error(f"Error processing stream: {str(e)}")
            raise

        logger.info("Finished processing stream")

    def _process_response(self, response):
        """Process non-streaming response from Bedrock"""
        response_body = json.loads(response.get("body").read())
        logger.info(f"Received non-streaming response: {json.dumps(response_body, indent=2)}")
        
        return {
            "choices": [{
                "message": {
                    "content": response_body.get("content", ""),
                    "role": "assistant"
                },
                "finish_reason": "stop"
            }]
        }
