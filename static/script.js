const socket = io.connect('http://localhost:5000');

socket.on('message', function(msg) {
    console.log('Received message: ' + msg);
});

// Function to send a message
function sendMessage() {
    const message = document.getElementById('messageInput').value;
    socket.send(message);
}
