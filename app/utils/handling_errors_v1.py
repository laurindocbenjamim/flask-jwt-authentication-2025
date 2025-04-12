

from flask import make_response, render_template, redirect, jsonify
from werkzeug.exceptions import HTTPException
from flask_limiter.errors import RateLimitExceeded
from app.utils import logger, get_message

image_list = [
    {"400": 'https://www.prontomarketing.com/wp-content/uploads/2022/12/how-to-fix-400-bad-requst-error-wordpress.png', "message": "Bad Request"},
    {"401": 'https://www.asktheegghead.com/wp-content/uploads/2019/12/401-error-wordpress-featured-image.jpg', "message": "Unauthorized"},
    {"403": 'https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-403.jpeg', "message": "Forbidden"},
    {"404": 'https://atlassianblog.wpengine.com/wp-content/uploads/2017/12/44-incredible-404-error-pages@3x.png', "message": "Not Found"},
    {"405": 'https://www.ionos.co.uk/digitalguide/fileadmin/DigitalGuide/Teaser/405-Method-Not-Allowed-t.jpg', "message": "Method Not Allowed"},
    {"415": 'https://sitechecker.pro/wp-content/uploads/2023/07/415-status-code.png', "message": "Unsupported Media Type"},
    {"429": 'https://sitechecker.pro/wp-content/uploads/2023/07/429-status-code.png', "message": "Too Many Requests"},
    {"500": 'https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png', "message": "Internal Server Error"},
    {"502": 'https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-502.jpeg', "message": "Bad Gateway"},
    {"503": 'https://www.lifewire.com/thmb/3Zne74PQmtY62N1E02VkiNg78bQ=/768x0/filters:no_upscale():max_bytes(150000):strip_icc()/shutterstock_717832600-Converted-5a29aaf3b39d030037b2cda9.png', "message": "Service Unavailable"},
    {"504": 'https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-504.jpeg', "message": "Gateway Timeout"},
]

def haddling_errors(app, CSRFError):
    """Handle errors and return a JSON response"""

    # Error Handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Handle rate limit exceeded errors"""
        app.logger.error('. %s', e)
        get_message(e, type='debug')
        return jsonify(status_code=429, error="Too many requests. Please try again later.")

    @app.errorhandler(CSRFError)
    def handler_csrf_error(e):
        app.logger.error('CSRF catched Error. %s', e)
        get_message(e, type='debug')
        return jsonify(status_code=400, error=e.description)


    @app.errorhandler(400)
    def handle_error_400(e):
        
        app.logger.error('Bad request. %s', e)
        get_message(e, type='debug')
        error_code = 400
        error_image = next((error["400"] for error in image_list if "400" in error), "Bad Request")
        error_description = next((error["400"] for error in image_list if "400" in error), "Bad Request")
        error_message = f"Code {error_code} - Bad Request"
        error_description = "Bad Request. The server could not understand the request due to invalid syntax."
        #error_description = str(e)
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Bad Request'
        
        
        return response
    

    @app.errorhandler(401)
    def handle_error_401(e):
        app.logger.error('Unauthorized access. %s', e)
        get_message(e, type='debug')
        error_code = 401
        error_image = next((error["401"] for error in image_list if "401" in error), "Unauthorized")
        error_description = next((error["401"] for error in image_list if "401" in error), "Unauthorized")
        error_message = f"Code {error_code} - Unauthorized"
        error_description = "You do not have permission to access this resource."
        #error_description = str(e)
        
        response = make_response(render_template('errors.html', title=error_code, message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Unauthorized'
        
        
        return response
    
    @app.errorhandler(403)
    def handle_error_403(e):

        app.logger.error('Access permission deniyed. %s', e)
        get_message(e, type='debug')
        error_code = 403
        error_message = f" Code {error_code} - Forbidden"
        error_image = next((error["403"] for error in image_list if "403" in error), "Forbidden")
        error_description = next((error["403"] for error in image_list if "403" in error), "Forbidden")
        error_description = "You do not have permission to access this resource."
       
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Forbidden'
        #from ..config_headers import set_header_params
        #set_header_params(response)
        #get_message(e, type='debug')
        
        return response
    

    @app.errorhandler(404)
    def handle_error_404(e):

        app.logger.error('Resources requested not Found. %s', e)
        get_message(e, type='debug')
        error_code = 404
        error_image = next((error["404"] for error in image_list if "404" in error), "Not Found")
        error_description = next((error["404"] for error in image_list if "404" in error), "Not Found")
        
        error_message = f" Code {error_code} - Not Found"
        error_description = "The requested resource was not found on the server."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Not Found'
        
        
        return response
    
    @app.errorhandler(405)
    def handle_error_405(e):

        app.logger.error('Method not allowed. %s', e)
        get_message(e, type='debug')
        error_code = 405
        error_image = next((error["405"] for error in image_list if "405" in error), "Method Not Allowed")
        error_description = next((error["405"] for error in image_list if "405" in error), "Method Not Allowed")
        
        error_message = f" Code {error_code} - Method Not Allowed"
        error_description = "The method specified in the request is not allowed for the resource."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Method Not Allowed'
        
        
        return response
    
    @app.errorhandler(415)
    def handle_error_405(e):

        app.logger.error('Unsuported media type. %s', e)
        get_message(e, type='debug')
        error_code = 415
        error_image = next((error["415"] for error in image_list if "415" in error), "Unsupported Media Type")
        error_description = next((error["415"] for error in image_list if "415" in error), "Unsupported Media Type")
        
        error_message = f" Code {error_code} - Unsupported Media Type"
        error_description = "The server refuses to accept the request because the payload format is in an unsupported format."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Unsupported Media Type'
        
        
        return response
    
    # Custom error handler for rate limit exceeded
    @app.errorhandler(RateLimitExceeded)
    def ratelimit_handler(e):

        app.logger.error('Too many requests. %s', e)
        get_message(e, type='debug')
        return jsonify({
            "error": "Too many requests",
            "message": "You have exceeded your request limit. Please try again later.",
            "status_code": 429
        }), 429
    
    @app.errorhandler(500)
    def handle_error_500(e):

        app.logger.error('Internal Server Error. %s', e)
        get_message(e, type='debug')
        error_code = 500
        error_image = next((error["500"] for error in image_list if "500" in error), "Internal Server Error")
        error_description = next((error["500"] for error in image_list if "500" in error), "Internal Server Error")
        
        error_message = f" Code {error_code} - Internal Server Error"
        error_description = "The server encountered an internal error and was unable to complete your request."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                         error_image=error_image, error_code=error_code), error_code)
        response = jsonify(title=error_code, error_message=error_message, error_description=error_description, 
                                         error_image=error_image, error_code=error_code)
        response.headers['X-Something'] = 'Internal Server Error'
        
        
        return response
    
    @app.errorhandler(503)
    def handle_error_503(e):

        app.logger.error('Service Unavailable%s', e)
        get_message(e, type='debug')
        error_code = 503
        error_image = next((error["503"] for error in image_list if "503" in error), "Service Unavailable")
        error_description = next((error["503"] for error in image_list if "503" in error), "Service Unavailable")
        
        error_message = f" Code {error_code} - Service Unavailable"
        error_description = "The server encountered an Service Unavailable and was unable to complete your request."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                         error_image=error_image, error_code=error_code), error_code)
        response = jsonify(title=error_code, error_message=error_message, error_description=error_description, 
                                         error_image=error_image, error_code=error_code)
        response.headers['X-Something'] = 'Internal Server Error'
        
        
        return response

    @app.errorhandler(NameError)
    def handle_name_error(e):

        app.logger.error('File is too large. %s', e)
        get_message(e, type='debug')
        error_code = 500
        error_message = "NameError: A variable or function is not defined."
        error_description = str(e)
        error_image = "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png"  # Reusing the 500 error image

        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                                 error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'NameError'
        
        return response
    
    @app.errorhandler(FileNotFoundError)
    def handle_file_not_found_error(e):

        app.logger.error('File is too large. %s', e)
        get_message(e, type='debug')
        error_code = 500
        error_message = "FileNotFoundError: The specified file was not found."
        error_description = str(e)
        error_image = "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png"  # Reusing the 500 error image

        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                                 error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'NameError'
        error_image = "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png"
    
    @app.errorhandler(TypeError)
    def handle_type_error(e):

        app.logger.error('File is too large. %s', e)
        get_message(e, type='debug')
        error_code = 500
        error_message = "TypeError: An operation or function is applied to an object of inappropriate type."
        error_description = str(e)
        error_image = "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png"  # Reusing the 500 error image

        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                                 error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'TypeError'
        
        return response