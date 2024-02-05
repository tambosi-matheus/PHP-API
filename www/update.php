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
    if(empty($data['email']) || empty($data['pwrd']) || !isset($data['username'], $data['surname'], $data['nickname'])){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Missing Arguments']);
        exit;
    }

    // Extract input from data
    $email = $data['email'];
    $password = $data['pwrd'];
    $newPassword = !empty($data['newPwrd']) ? password_hash($data['newPwrd'], PASSWORD_BCRYPT) : password_hash($data['pwrd'], PASSWORD_BCRYPT);
    $username = $data['username'];
    $surname = $data['surname'];
    $nickname = $data['nickname'];

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

    // Check if password is correct
    if(!password_verify($password, $dbPassword)){
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid password']);
        exit;
    }

    // Execute SQL Query
    $stmt = $pdo->prepare('UPDATE main set pwrd=:pwrd, username=:username, surname=:surname, nickname=:nickname WHERE email=:email');
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);  
    $stmt->bindParam(':pwrd', $newPassword, PDO::PARAM_STR);
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->bindParam(':surname', $surname, PDO::PARAM_STR);
    $stmt->bindParam(':nickname', $nickname, PDO::PARAM_STR);
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