Web Messenger

This is a secure web-based messenger application with WebSocket-based communication, user authentication, and conference messaging. The application consists of a server, a client, and a Redis instance, all managed via Docker Compose.

Prerequisites

Before you begin, ensure you have the following installed on your system:





Docker: To build and run the containers.



Docker Compose: To manage multi-container setup.



A modern web browser (e.g., Chrome, Firefox) to access the client interface.

Project Structure





server/: Contains the WebSocket server code (server.py) and the database file (chat.db).



client/: Contains the client-side code (e.g., index.html, JavaScript, and CSS).



docker-compose.yml: Defines the services (server, client, and Redis) and their configurations.

Setup and Running the Application

Follow these steps to set up and run the Web Messenger application.

Step 1: Clone the Repository

Clone the repository to your local machine:

git clone <repository-url>
cd web-messenger

Step 2: Verify Directory Structure

Ensure the following directories and files exist:





server/



client/



docker-compose.yml

Step 3: Build and Start the Containers

Run the following command to build and start the containers:

docker-compose up -d --build





The -d flag runs the containers in detached mode (in the background).



The --build flag ensures that the Docker images are rebuilt if there are changes.

This will start:





The server on port 8765 (WebSocket server).



The client on port 8000 (web interface).



A Redis instance for potential future use.

Step 4: Verify the Server is Running

Check the server logs to ensure it started correctly:

docker logs web-messenger-server-1

You should see output similar to:

Starting server...
Created directory /app/master_key
Checking if /app/master_key/master_key.txt exists: False
Is /app/master_key/master_key.txt a file? False
Is /app/master_key/master_key.txt a directory? False
MASTER_KEY not set in environment, checking file...
MASTER_KEY file not found, generating a new one...
New MASTER_KEY generated and saved to /app/master_key/master_key.txt
Master key initialized
Initializing database...
Database initialized
Starting WebSocket server on ws://0.0.0.0:8765

If you see errors, refer to the Troubleshooting section.

Step 5: Verify the Ports

Ensure the server and client are accessible:





Server: Port 8765 (WebSocket)



Client: Port 8000 (web interface)

Check if the ports are listening:

netstat -an | grep 8765
netstat -an | grep 8000

Expected output for port 8765:

tcp4       0      0  *.8765                 *.*                    LISTEN

Expected output for port 8000:

tcp4       0      0  *.8000                 *.*                    LISTEN

Step 6: Access the Web Interface

Open your browser and navigate to:

http://localhost:8000

You should see the login screen.

Step 7: Log In

Use the default admin credentials to log in:





Username: admin



Password: WhereMainShell

Click the "Login" button. Upon successful login, the login screen should disappear, and the chat interface should appear.

Expected browser console output (F12 → Console):

WebSocket connected
Login attempt: admin WhereMainShell
Sending login message
Received message: {type: "login_success", session_token: "...", is_admin: true}

Troubleshooting

Server Fails to Start

If the server fails to start, check the logs:

docker logs web-messenger-server-1





Error: IsADirectoryError: [Errno 21] Is a directory: '/app/master_key/master_key.txt'





This indicates a conflict with the master_key.txt file. To resolve:

docker-compose down -v
docker volume rm web-messenger_master-key-volume
docker-compose up -d --build



This removes the old volume and starts fresh.

Client Cannot Connect to WebSocket

If the client fails to connect (e.g., you see "WebSocket connection failed" in the browser console):





Ensure the server is running and port 8765 is open (netstat -an | grep 8765).



Verify that the WebSocket URL in the client code is correct (ws://localhost:8765).

Login Fields Are Cleared Automatically

If the username and password fields are cleared while typing:





Open the browser console (F12 → Console) and look for errors or logs during input.



Ensure autocomplete="off" is set on the input fields in client/index.html:

<input type="text" id="username" placeholder="Username" autocomplete="off">
<input type="password" id="password" placeholder="Password" autocomplete="off">

Stopping the Application

To stop the application, run:

docker-compose down

To stop and remove all volumes (resetting the application state):

docker-compose down -v

Notes





The MASTER_KEY for encryption is automatically generated and stored in a Docker Volume (master-key-volume) on first run. It persists between restarts.



The database (chat.db) is stored in the server/ directory and persists between runs.



The default admin user is admin with password WhereMainShell. You can register new users via the admin interface after logging in.