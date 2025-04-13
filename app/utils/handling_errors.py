from flask import make_response, render_template, jsonify
from werkzeug.exceptions import HTTPException
from flask_limiter.errors import RateLimitExceeded
from app.utils import logger, get_message
from typing import Dict, List, Any, Optional, Union
from flask_jwt_extended import current_user
from flask import request, g  # Add this with your other Flask imports

# Constants and Configuration
ERROR_CONFIG: List[Dict[str, Any]] = [
    {
        "code": 400,
        "image": "https://www.prontomarketing.com/wp-content/uploads/2022/12/how-to-fix-400-bad-requst-error-wordpress.png",
        "message": "Bad Request",
        "description": "The server could not understand the request due to invalid syntax."
    },
    {
        "code": 401,
        "image": "https://www.asktheegghead.com/wp-content/uploads/2019/12/401-error-wordpress-featured-image.jpg",
        "message": "Unauthorized",
        "description": "You do not have permission to access this resource."
    },
    {
        "code": 403,
        "image": "https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-403.jpeg",
        "message": "Forbidden",
        "description": "Access to this resource is forbidden."
    },
    {
        "code": 404,
        "image": "https://atlassianblog.wpengine.com/wp-content/uploads/2017/12/44-incredible-404-error-pages@3x.png",
        "message": "Not Found",
        "description": "The requested resource was not found on the server."
    },
    {
        "code": 405,
        "image": "https://www.ionos.co.uk/digitalguide/fileadmin/DigitalGuide/Teaser/405-Method-Not-Allowed-t.jpg",
        "message": "Method Not Allowed",
        "description": "The method specified in the request is not allowed for the resource."
    },
    {
        "code": 415,
        "image": "https://sitechecker.pro/wp-content/uploads/2023/07/415-status-code.png",
        "message": "Unsupported Media Type",
        "description": "The server refuses to accept the request because the payload format is unsupported."
    },
    {
        "code": 429,
        "image": "https://sitechecker.pro/wp-content/uploads/2023/07/429-status-code.png",
        "message": "Too Many Requests",
        "description": "You have exceeded your request limit. Please try again later."
    },
    {
        "code": 500,
        "image": "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png",
        "message": "Internal Server Error",
        "description": "The server encountered an internal error and was unable to complete your request."
    },
    {
        "code": 502,
        "image": "https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-502.jpeg",
        "message": "Bad Gateway",
        "description": "The server received an invalid response from the upstream server."
    },
    {
        "code": 503,
        "image": "https://www.lifewire.com/thmb/3Zne74PQmtY62N1E02VkiNg78bQ=/768x0/filters:no_upscale():max_bytes(150000):strip_icc()/shutterstock_717832600-Converted-5a29aaf3b39d030037b2cda9.png",
        "message": "Service Unavailable",
        "description": "The server is currently unable to handle the request."
    },
    {
        "code": 504,
        "image": "https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-504.jpeg",
        "message": "Gateway Timeout",
        "description": "The server did not receive a timely response from the upstream server."
    }
]

# Default error configuration for unhandled exceptions
DEFAULT_ERROR_CONFIG = {
    "image": "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png",
    "message": "Internal Server Error",
    "description": "An unexpected error occurred while processing your request."
}


def _log_error_details(
    error: Exception,
    error_code: int,
    context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log error details with context using our enhanced logging system.
    
    Args:
        error: The exception that occurred
        error_code: HTTP status code
        context: Additional context information
    """
    log_context = {
        'error_code': error_code,
        'handler': 'error_handler',
        **(context or {})
    }
    
    if isinstance(error, HTTPException):
        log_context.update({
            'error_name': getattr(error, 'name', ''),
            'description': getattr(error, 'description', '')
        })
    
    # Use different log levels based on error type
    if error_code == 429:
        get_message(error, 'warn', "Rate limit exceeded", log_context)
    elif 400 <= error_code < 500:
        get_message(error, 'warning', "Client error occurred", log_context)
    else:
        get_message(error, 'error', "Server error occurred", log_context)


def _get_error_config(error_code: int) -> Dict[str, Any]:
    """Get the configuration for a specific error code."""
    return next(
        (config for config in ERROR_CONFIG if config["code"] == error_code),
        {"code": error_code, **DEFAULT_ERROR_CONFIG}
    )

def _log_error(error: Exception, error_type: str = "debug") -> None:
    """Log the error and send a debug message."""
    logger.error('%s: %s', error.__class__.__name__, str(error))
    get_message(error, type=error_type)
    get_message(error, error_type, 'Failed to complete operation', {'user': current_user.id})

def _create_error_response(
    error_code: int,
    error: Optional[Exception] = None,
    custom_message: Optional[str] = None,
    custom_description: Optional[str] = None,
    json_response: bool = False,
    additional_context: Optional[Dict[str, Any]] = None
) -> Union[Dict[str, Any], make_response]:
    """
    Enhanced version with integrated logging.
    """
    if error:
        _log_error_details(error, error_code, additional_context)
    
    config = _get_error_config(error_code)
    
    response_data = {
        "title": error_code,
        "error_code": error_code,
        "error_message": custom_message or f"Code {error_code} - {config['message']}",
        "error_description": custom_description or config["description"],
        "error_image": config["image"]
    }
    
    if json_response:
        response = jsonify(response_data)
    else:
        response = make_response(
            render_template('errors.html', **response_data),
            error_code
        )
    
    response.headers['X-Error-Code'] = str(error_code)
    response.headers['X-Error-Message'] = config['message']
    
    return response

def handle_errors(app, CSRFError) -> None:
    """Register error handlers with integrated logging."""
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e: CSRFError):
        return _create_error_response(
            400, 
            e,
            custom_description=e.description,
            json_response=True,
            additional_context={'error_type': 'csrf'}
        )
    
    @app.errorhandler(RateLimitExceeded)
    @app.errorhandler(429)
    def handle_rate_limit(e: Union[RateLimitExceeded, HTTPException]):
        return _create_error_response(
            429, 
            e,
            json_response=True,
            additional_context={'error_type': 'rate_limit'}
        )
    
    @app.errorhandler(ValueError)
    def handle_rate_limit(e: ValueError):
        return _create_error_response(
            500, 
            e,
            json_response=True,
            additional_context={'error_type': 'rate_limit'}
        )
    

    # Python built-in exceptions
    @app.errorhandler(Exception)
    def handle_generic_exception(e: Exception):
        # Prevent recursive handling
        if getattr(e, '_handled', False):
            return jsonify({
                "status": "error",
                "message": str(e),
                "error_code": 500
            }), 500
        
        try:
            return _create_error_response(
                500,
                e,
                json_response=True,
                additional_context={
                    'error_type': 'unhandled_exception',
                    'request_id': getattr(request, 'request_id', None)
                }
            )
        except Exception as fatal_error:
            # Last resort fallback
            return jsonify({
                "status": "critical_error",
                "message": "The server encountered a critical failure",
                "error_code": 500
            }), 500

    @app.errorhandler(400)
    def handle_400(e: HTTPException):
        return _create_error_response(400, e)
    
    @app.errorhandler(401)
    def handle_401(e: HTTPException):
        return _create_error_response(401, e)
    
    @app.errorhandler(403)
    def handle_403(e: HTTPException):
        return _create_error_response(403, e)
    
    # Example of a specific error handler with custom logging
    @app.errorhandler(404)
    def handle_404(e: HTTPException):
        return _create_error_response(
            404,
            e,
            additional_context={
                'request_path': request.path,
                'referrer': request.referrer
            }
        )
    
    
    @app.errorhandler(405)
    def handle_405(e: HTTPException):
        return _create_error_response(405, e)
    
    @app.errorhandler(415)
    def handle_415(e: HTTPException):
        return _create_error_response(415, e)
    
    @app.errorhandler(500)
    def handle_500(e: HTTPException):
        return _create_error_response(
            500,
            e,
            json_response=True,
            additional_context={
                'error_type': 'server_error',
                'request_id': getattr(request, 'request_id', None)  # Safely get the request ID
            }
        )
    
    @app.errorhandler(503)
    def handle_503(e: HTTPException):
        return _create_error_response(503, e, json_response=True)
    
    # Handle Python built-in exceptions
    @app.errorhandler(NameError)
    def handle_name_error(e: NameError):
        return _create_error_response(
            500, 
            e,
            custom_message="NameError: A variable or function is not defined.",
            custom_description=str(e)
        )
    
    @app.errorhandler(FileNotFoundError)
    def handle_file_not_found(e: FileNotFoundError):
        return _create_error_response(
            500,
            e,
            custom_message="FileNotFoundError: The specified file was not found.",
            custom_description=str(e)
        )
    
    @app.errorhandler(TypeError)
    def handle_type_error(e: TypeError):
        return _create_error_response(
            500,
            e,
            custom_message="TypeError: Operation applied to object of inappropriate type.",
            custom_description=str(e)
        )
    
    # Catch-all for other HTTP exceptions
    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        return _create_error_response(e.code, e)