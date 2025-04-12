


import os

# File you want to split
file_path = "your_large_file.pdf"
chunk_size = 25 * 1024 * 1024  # 25 MB

def split_media_file(file_path, chunk_size):
    file_size = os.path.getsize(file_path)
    print(f"Total file size: {file_size} bytes")

    base_name = os.path.splitext(file_path)[0]
    ext = os.path.splitext(file_path)[1]

    files=[]

    with open(file_path, "rb") as f:
        chunk_num = 1
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunk_file_name = f"{base_name}_part{chunk_num}{ext}"
            with open(chunk_file_name, "wb") as chunk_file:
                chunk_file.write(chunk)

            files.append(chunk_file_name)
            print(f"Created: {chunk_file_name} ({len(chunk)} bytes)")
            
            chunk_num += 1
    return chunk_file_name


#split_media_file(file_path, chunk_size)
