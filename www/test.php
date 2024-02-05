<?php
require_once 'config.php';
// Set the content type to JSON
header('Content-Type: application/json');
// Handle HTTP methods
$method = $_SERVER['REQUEST_METHOD'];
switch ($method) 
{
    case 'GET':
        if(isset($_GET['email']))
        {
            $email = isset($_GET['email']) ? $_GET['email'] : null;

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400); // Bad Request
                echo json_encode(['error' => 'Invalid email']);
                exit;
            }

            $stmt = $pdo->prepare('SELECT email, username, surname, nickname FROM main WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) 
                echo json_encode(['message' => 'User found', 'user' => $user]);
            else {
                http_response_code(404); // Not Found
                echo json_encode(['error' => 'User not found']);
            }
        }
        else{
            $stmt = $pdo->query('SELECT email, username, surname, nickname FROM main');
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['Here is a list of all users on our database' => $result]);
        }        
    break;
    case 'POST':
        $data = json_decode(file_get_contents('php://input'), true);

        if (!isset($data['email'], $data['pwrd'], $data['username'], $data['surname'], $data['nickname'])) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Incomplete data provided']);
            break;
        }
    
        $email = $data['email'];
        $password = $data['pwrd'];
        $username = $data['username'];
        $surname = $data['surname'];
        $nickname = $data['nickname'];
    
        $stmt = $pdo->prepare('INSERT INTO main (email, pwrd, username, surname, nickname) VALUES (?, ?, ?, ?, ?)');
        $success = $stmt->execute([$email, $password, $username, $surname, $nickname]);
    
        // Check if the insertion was successful
        if ($success) {
            http_response_code(201); // Created
            echo json_encode(['message' => 'User added successfully']);
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(['error' => 'Failed to add user']);
        }
    break;
    // For some reason PUT/DELETE is not working, I have an active thread trying to find a solution
    // https://serverfault.com/questions/1152896/error-405-with-put-on-nginx?noredirect=1#comment1507280_1152896
    case 'PUT':
        $data = json_decode(file_get_contents('php://input'), true);

        // Check if required fields are present in the request
        if (!isset($data['email'], $data['pwrd'], $data['username'], $data['surname'], $data['nickname'])) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Incomplete data provided']);
            exit;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Invalid email']);
            exit;
        }

        // Extract data from the request
        $email = $data['email'];
        $password = $data['pwrd'];
        $username = $data['username'];
        $surname = $data['surname'];
        $nickname = $data['nickname'];
        
        
        // Prepare and execute a database query to update the user by email
        $stmt = $pdo->prepare('UPDATE main SET pwrd=?, username=?, surname=?, nickname=? WHERE email=?');
        $stmt->execute([$password, $username, $surname, $nickname, $email]);

        // Check if any rows were affected
        $rowCount = $stmt->rowCount();
        if ($rowCount > 0) {
            echo json_encode(['message' => 'User updated successfully']);
        } else {
            http_response_code(404); // Not Found
            echo json_encode(['error' => 'User not found']);
        }
    break;
    case 'DELETE':
        
        parse_str(file_get_contents("php://input"), $deleteParams);

        $email = isset($deleteParams['email']) ? $deleteParams['email'] : null;

        if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
            http_response_code(400); // Bad Request
            echo json_encode(['error' => 'Invalid email parameter']);
            exit;
        }
        
        $stmt = $pdo->prepare('DELETE FROM main WHERE email=?');
        $stmt->execute([$email]);
        
        echo json_encode(['message' => 'User deleted successfully']);
    break;
    default:
        // Invalid method
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
    break;
}
?>