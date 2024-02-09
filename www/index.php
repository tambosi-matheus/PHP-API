<?php
require_once 'config.php';
// Set the content type to JSON
header('Content-Type: application/json');
// Handle HTTP methods
$method = $_SERVER['REQUEST_METHOD'];
switch ($method) 
{
    case 'GET':
        $email = !empty($_GET['email']) ? $_GET['email'] : null;
        $search = !empty($_GET['search']) ? $_GET['search'] : null;

        // Find users with search term
        if($search){    
            // Execute SQL Query        
            $stmt = $pdo->prepare('SELECT email, cpf, first_name, last_name FROM users WHERE first_name = ? OR last_name = ? or cpf= ?');
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
            // Validade email
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400); // Bad Request
                echo json_encode(['error' => 'Invalid email']);
                exit;
            }

            // Execute SQL Query
            $stmt = $pdo->prepare('SELECT email, cpf, first_name, last_name FROM users WHERE email = ?');
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
            $stmt = $pdo->query('SELECT email, cpf, first_name, last_name FROM users');
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['Users' => $result]);
        }        
    break;
    case 'POST':
        $data = json_decode(file_get_contents('php://input'), true);

        // Validade input
        if (empty($data['email']) || empty($data['pwrd']) || empty($data['cpf'])  || !isset($data['first_name'], $data['last_name'])) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Incomplete data provided']);
            exit;
        }
        
        // Extract input from data
        $email = $data['email'];
        $password = password_hash($data['pwrd'], PASSWORD_BCRYPT); //Encrypt password
        $first_name = $data['first_name'];
        $last_name = $data['last_name'];
        $cpf = $data['cpf'];
        
        // Validade email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Invalid email']);
            exit;
        }

        // Check if the email exists in the database
        $stmt = $pdo->prepare('SELECT email FROM users WHERE email = ?');
        $stmt->execute([$email]);
        if($stmt->fetchColumn()){
            http_response_code(400);
            echo json_encode(['error' => 'User already exists']);
            exit;
        }
        
        // Execute SQL Query
        $stmt = $pdo->prepare('INSERT INTO users (email, cpf, pwrd, first_name, last_name) VALUES (:email, :cpf, :pwrd, :first_name, :last_name)');
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':cpf', $cpf, PDO::PARAM_STR);
        $stmt->bindParam(':pwrd', $password, PDO::PARAM_STR);
        $stmt->bindParam(':first_name', $first_name, PDO::PARAM_STR);
        $stmt->bindParam(':last_name', $last_name, PDO::PARAM_STR);
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