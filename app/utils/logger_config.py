import logging
import os
from logging.handlers import TimedRotatingFileHandler

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Check if the directory exists, if not, create it
if not os.path.exists('app/static/logs/'):
    os.makedirs('app/static/logs/')

# check if the file exist, if not, create it
if not os.path.exists('app/static/logs/logs.log'):
    # Create the file
    with open('app/static/logs/logs.log', 'w') as file:
        file.write('# THIS IS A LOG FILE \n\n\n')

# Create a file handler
#handler = TimedRotatingFileHandler('app.log', when='midnight', interval=1)
#handler.suffix = "%Y-%m-%d"
file_handler = logging.FileHandler('app/static/logs/logs.log')
file_formatter = logging.Formatter('[%(asctime)s] - %(name)s - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(file_formatter)

# Create a console handler
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
console_handler.setFormatter(console_formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Log some messages
#logger.debug('This is a debug message')
#logger.info('This is an info message')
#logger.warning('This is a warning message')
#logger.error('This is an error message')
#logger.critical('This is a critical message')


def get_message(e, type='debug', message=None):
    if type == 'debug':
        code = e
        name = e
        description = e
        logger.debug('\n\n\n\n========================  DEBUGING  =======================================\
            \n\nCODE:%s \nNAME:%s \
            \nERROR: \n%s\
            \nMESSAGE: \n%s\
            \n _________________________\
            DESCRIPTION\
            ___________________________\n %s ', code, name, e, description, message)
    elif type == 'info':
        code = e.code
        name = e.name
        description = e.description
        logger.info('\n===============================================================\
            \nCODE:%s \nNAME:%s \
            \nERROR: \n%s\
            \n _________________________\
            DESCRIPTION\
            ___________________________\n %s ', code, name, e, description)
    elif type == 'warn':
        code = e.code
        name = e.name
        description = e.description
        logger.warning('\n===========================================================================================\
            \nCODE:%s \nNAME:%s \
            \nERROR: \n%s\
            \n _________________________\
            DESCRIPTION\
            ___________________________\n %s ', code, name, e, description)
    elif type == 'error':
        code = e.code
        name = e.name
        description = e.description
        logger.error('\n===============================================================\
            \nCODE:%s \nNAME:%s \
            \nERROR: \n%s\
            \n _________________________\
            DESCRIPTION\
            ___________________________\n %s ', code, name, e, description)
    elif type == 'critical':
        code = e.code
        name = e.name
        description = e.description
        logger.critical('\n===============================================================\
            \nCODE:%s \nNAME:%s \
            \nERROR: \n%s\
            \n _________________________\
                        DESCRIPTION\
                        ___________________________\n %s ', code, name, e, description)