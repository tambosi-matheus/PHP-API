<?php
require_once 'config.php';
// Set the content type to JSON
header('Content-Type: application/json');
// Handle HTTP methods
$method = $_SERVER['REQUEST_METHOD'];
if($method == 'POST')
{
    $data = json_decode(file_get_contents('php://input'), true);

    // Validade data
    if(empty($data['email']) || empty($data['pwrd'])){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Missing Arguments']);
        exit;
    }

    // Extract input from data
    $email = $data['email'];
    $password = $data['pwrd'];

    // Validade email format
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid email']);
        exit;
    }

    // Check if the email exists in the database
    $stmt = $pdo->prepare('SELECT pwrd FROM main WHERE email = ?');
    $stmt->execute([$email]);
    $dbPassword = $stmt->fetchColumn();
    if(!$dbPassword){
        http_response_code(404); //Bad Request
        echo json_encode(['error' => 'User not found']);
        exit;
    }

    // Verify if password is correct
    if(!password_verify($password, $dbPassword)){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid password']);
        exit;
    }

    // Execute SQL Query
    $stmt = $pdo->prepare('DELETE FROM main WHERE email=?');
    $stmt->execute([$email]);
    
    // Return result
    // http_response_code(204); // No Content
    echo json_encode(['message' => 'User deleted successfully']);
}
else{
    // Invalid method
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
}

?>