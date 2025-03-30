

from flask import make_response, render_template, redirect, jsonify

image_list = [
    {"400": 'https://www.prontomarketing.com/wp-content/uploads/2022/12/how-to-fix-400-bad-requst-error-wordpress.png', "message": "Bad Request"},
    {"401": 'https://www.asktheegghead.com/wp-content/uploads/2019/12/401-error-wordpress-featured-image.jpg', "message": "Unauthorized"},
    {"403": 'https://www.online-tech-tips.com/wp-content/uploads/2021/06/http-403.jpeg', "message": "Forbidden"},
    {"404": 'https://atlassianblog.wpengine.com/wp-content/uploads/2017/12/44-incredible-404-error-pages@3x.png', "message": "Not Found"},
    {"405": 'https://www.ionos.co.uk/digitalguide/fileadmin/DigitalGuide/Teaser/405-Method-Not-Allowed-t.jpg', "message": "Method Not Allowed"},
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
        return jsonify(status_code=429, error="Too many requests. Please try again later.")

    @app.errorhandler(CSRFError)
    def handler_csrf_error(e):
        return jsonify(status_code=400, error=e.description)


    @app.errorhandler(400)
    def handle_error_400(e):
        
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

        error_code = 405
        error_image = next((error["405"] for error in image_list if "405" in error), "Method Not Allowed")
        error_description = next((error["405"] for error in image_list if "405" in error), "Method Not Allowed")
        
        error_message = f" Code {error_code} - Method Not Allowed"
        error_description = "The method specified in the request is not allowed for the resource."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Method Not Allowed'
        
        
        return response
    
    @app.errorhandler(500)
    def handle_error_500(e):

        error_code = 500
        error_image = next((error["500"] for error in image_list if "500" in error), "Internal Server Error")
        error_description = next((error["500"] for error in image_list if "500" in error), "Internal Server Error")
        
        error_message = f" Code {error_code} - Internal Server Error"
        error_description = "The server encountered an internal error and was unable to complete your request."
        
        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                             error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'Internal Server Error'
        
        
        return response

    @app.errorhandler(NameError)
    def handle_name_error(e):
        error_code = 500
        error_message = "NameError: A variable or function is not defined."
        error_description = str(e)
        error_image = "https://miro.medium.com/v2/resize:fit:1400/1*2Z41mMgjOxkUUuvIwd7Djw.png"  # Reusing the 500 error image

        response = make_response(render_template('errors.html', title=error_code, error_message=error_message, error_description=error_description, 
                                                 error_image=error_image, error_code=error_code), error_code)
        response.headers['X-Something'] = 'NameError'
        
        return response