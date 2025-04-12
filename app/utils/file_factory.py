

import os, json, base64

class MyGeneralFileFactory:

    def create(self, *, content, filepath, type_of):
        #if not os.path.exists(filepath):
        #    return False
        
        match type_of:
            case 'docx':
                try:
                    with open(filepath, "w", encoding="utf-8") as file:
                        file.write(content)
                except Exception as e:
                    raise ValueError(f"Filed to create file ({str(e)})")
            case 'md':
                try:
                    with open(filepath, "w") as file:
                        file.write(content)
                except Exception as e:
                    raise ValueError(f"Filed to create file ({str(e)})")
            case 'html':
                try:
                    with open(filepath, "w") as file:
                        file.write(content)
                except Exception as e:
                    raise ValueError(f"Filed to create file ({str(e)})")

            case 'BASE64_ENCODED_STRING_DOCX':
                
                if content:
                    # Example Base64 response
                    # Decode and save as a DOCX file
                    with open(filepath, "wb") as file:
                        file.write(base64.b64decode(content))
            case 'json':
                # Save to a JSON file
                with open(filepath, "w", encoding="utf-8") as file:
                    json.dump(content, file, indent=4, ensure_ascii=False)

        return True
        