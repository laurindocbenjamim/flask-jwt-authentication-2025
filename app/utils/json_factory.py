
import json
import re

def handle_ai_response_json(ai_response_json):
    # Parse JSON string into a Python dictionary
    json_string=str(ai_response_json).replace('```json', '').replace('```', '').strip()
    

    # Ensure correct encoding
    json_bytes = json_string.encode("utf-8")
    json_string = json_bytes.decode("utf-8")


    # Remove any trailing commas that may exist
    json_string = re.sub(r',\s*}', '}', json_string)  # For commas before closing curly braces
    json_string = re.sub(r',\s*]', ']', json_string)  # For commas before closing square brackets
    
    return json_string

def parse_the_ai_json_content_to_string(*,json_string):
    # Parse JSON safely
    try:
        data = json.loads(json_string)
        return data
    except json.JSONDecodeError as e:
        return "JSON Decode Error: {e}"