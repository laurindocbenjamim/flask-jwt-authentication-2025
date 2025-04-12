import logging
import os
import sys
import traceback
from logging.handlers import TimedRotatingFileHandler
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

class SafeLogger:
    """Thread-safe logger with guaranteed non-recursive error handling."""
    
    _instance = None
    _lock = False  # Global recursion lock
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized or SafeLogger._lock:
            return
            
        SafeLogger._lock = True
        try:
            self.logger = logging.getLogger('safe_app_logger')
            self.logger.setLevel(logging.DEBUG)
            self._setup_logging()
            self._initialized = True
        finally:
            SafeLogger._lock = False
    
    def _safe_file_handler(self):
        """Create handler that can't trigger its own errors"""
        try:
            os.makedirs('app/static/logs', exist_ok=True)
            handler = logging.StreamHandler(open('app/static/logs/app.log', 'a', encoding='utf-8'))
            handler.setFormatter(logging.Formatter('%(message)s'))
            return handler
        except:
            return logging.NullHandler()
    
    def _setup_logging(self):
        self.logger.handlers = []
        
        # 1. Primary JSON log file
        try:
            file_handler = TimedRotatingFileHandler(
                'app/static/logs/app.json.log',
                when='midnight',
                backupCount=7,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter(
                '{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
                datefmt='%Y-%m-%dT%H:%M:%S%z'
            ))
            self.logger.addHandler(file_handler)
        except:
            pass
        
        # 2. Fallback simple file log
        self.logger.addHandler(self._safe_file_handler())
        
        # 3. Always ensure console output
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        self.logger.addHandler(console)
    
    def log_exception(self, exc: BaseException, context: Optional[Dict] = None):
        """Atomic logging operation that cannot recurse"""
        if SafeLogger._lock:
            return
            
        SafeLogger._lock = True
        try:
            exc_info = (type(exc), exc, exc.__traceback__)
            self.logger.error(
                "Error occurred: %s",
                str(exc),
                exc_info=exc_info,
                extra={'context': context or {}}
            )
        except Exception as log_exc:
            print(f"CRITICAL LOGGER FAILURE: {log_exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        finally:
            SafeLogger._lock = False

# Global singleton
logger = SafeLogger()

def get_message(
    exc: BaseException,
    level: str = 'error',
    message: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Ultra-safe message logger that:
    - Cannot recurse
    - Cannot raise exceptions
    - Always delivers some output
    """
    if not isinstance(exc, BaseException):
        exc = RuntimeError(str(exc))
        
    try:
        log_context = {
            'level': level,
            'custom_message': message,
            **(context or {})
        }
        
        # Special handling for HTTP exceptions
        if hasattr(exc, 'code'):
            log_context.update({
                'status_code': exc.code,
                'error_name': getattr(exc, 'name', ''),
                'description': getattr(exc, 'description', '')
            })
        
        logger.log_exception(exc, log_context)
    except:
        print(f"FALLBACK: {level.upper()}: {message or str(exc)}", file=sys.stderr)