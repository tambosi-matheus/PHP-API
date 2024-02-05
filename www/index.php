<?php
require_once 'config.php';
// Set the content type to JSON
header('Content-Type: application/json');
// Handle HTTP methods
$method = $_SERVER['REQUEST_METHOD'];
switch ($method) 
{
    case 'GET':
        $email = isset($_GET['email']) ? $_GET['email'] : null;
        $search = isset($_GET['search']) ? $_GET['search'] : null;

        // Find users with search term
        if($search){    
            // Execute SQL Query        
            $stmt = $pdo->prepare('SELECT email, username, surname, nickname FROM main WHERE username = ? OR surname = ? OR nickname = ?');
            $stmt->execute([$search, $search, $search]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Return the result
            if(!$users){
                http_response_code(404); // Not Found
                echo json_encode((['error' => "No users match '{$search}'"]));
                exit;
            }
            echo json_encode($users);
        }
        // Get specific user
        else if($email)
        {
            $email = $_GET['email'];
            
            // Validade email
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400); // Bad Request
                echo json_encode(['error' => 'Invalid email']);
                exit;
            }

            // Execute SQL Query
            $stmt = $pdo->prepare('SELECT email, username, surname, nickname FROM main WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Return the result
            if ($user) 
                echo json_encode(['message' => 'User found', 'user' => $user]);
            else {
                http_response_code(404); // Not Found
                echo json_encode(['error' => 'User not found']);
            }
        }
        // Get all users in database
        else{
            $stmt = $pdo->query('SELECT email, username, surname, nickname FROM main');
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['Users' => $result]);
        }        
    break;
    case 'POST':
        $data = json_decode(file_get_contents('php://input'), true);

        // Validade input
        if (!isset($data['email'], $data['pwrd'], $data['username'], $data['surname'], $data['nickname'])) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Incomplete data provided']);
            break;
        }
        
        // Extract input from data
        $email = $data['email'];
        $password = password_hash($data['pwrd'], PASSWORD_BCRYPT); //Encrypt password
        $username = $data['username'];
        $surname = $data['surname'];
        $nickname = $data['nickname'];
        
        // Validade email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Invalid email']);
            exit;
        }
        
        // Execute SQL Query
        $stmt = $pdo->prepare('INSERT INTO main (email, pwrd, username, surname, nickname) VALUES (:email, :password, :username, :surname, :nickname)');
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':password', $password, PDO::PARAM_STR);
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->bindParam(':surname', $surname, PDO::PARAM_STR);
        $stmt->bindParam(':nickname', $nickname, PDO::PARAM_STR);
        $success = $stmt->execute();
    
        // Return the result
        if ($success) {
            http_response_code(201); // Created
            echo json_encode(['message' => 'User added successfully']);
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(['error' => 'Failed to add user']);
        }
    break;
    default:
        // Invalid method
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
    break;
}
?>