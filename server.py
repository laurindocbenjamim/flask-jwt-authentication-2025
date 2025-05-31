# Import livraries
import http.server
import ssl


#server_address =('0.0.0.0', 5000)
server_address =('192.168.1.252', 5000)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Create SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.pem') 

# Wrap the socket
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Serving on https://{server_address[0]}:{server_address[1]}")
httpd.server_forever()
