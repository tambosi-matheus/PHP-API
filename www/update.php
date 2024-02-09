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
    if(empty($data['email']) || empty($data['pwrd']) || !isset($data['first_name'], $data['last_name'], $data['cpf'])){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Missing Arguments']);
        exit;
    }

    // Extract input from data
    $email = $data['email'];
    $password = $data['pwrd'];
    $newPassword = !empty($data['newPwrd']) ? password_hash($data['newPwrd'], PASSWORD_BCRYPT) : password_hash($data['pwrd'], PASSWORD_BCRYPT);
    $first_name = $data['first_name'];
    $last_name = $data['last_name'];
    $cpf = $data['cpf'];

    // Validade email format
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid email']);
        exit;
    }

    // Check if the email exists in the database
    $stmt = $pdo->prepare('SELECT pwrd FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $dbPassword = $stmt->fetchColumn();
    if(!$dbPassword){
        http_response_code(404); //Bad Request
        echo json_encode(['error' => 'User not found']);
        exit;
    }

    // Check if password is correct
    if(!password_verify($password, $dbPassword)){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid password']);
        exit;
    }

    // Execute SQL Query
    $stmt = $pdo->prepare('UPDATE users set pwrd=:pwrd, first_name=:first_name, last_name=:last_name WHERE email=:email');
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);  
    $stmt->bindParam(':pwrd', $newPassword, PDO::PARAM_STR);
    $stmt->bindParam(':first_name', $first_name, PDO::PARAM_STR);
    $stmt->bindParam(':last_name', $last_name, PDO::PARAM_STR);
    $stmt->bindParam(':cpf', $cpf, PDO::PARAM_STR);
    $stmt->execute();

    // Return result
    //http_response_code(204); // No Content
    echo json_encode(['message' => 'User updated']);
}
else{
    // Invalid method
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
}

?>