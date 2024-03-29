<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Respect\Validation\Validator as v;
use Respect\Validation\Exceptions\NestedValidationException;
use Nyholm\Psr7\Response as Psr7Response;

require __DIR__ . '/vendor/autoload.php';

$jwt_secret = '4d20ab626c134f6e88bcb33fa2c5e1fcf279c037820a0530a73f95508fb96aa8';

$app = AppFactory::create();
$app->addBodyParsingMiddleware();

// Set up middleware for validating JWT

function getBearerToken(): ?string
{
    $headers = array_change_key_case(getallheaders(), CASE_LOWER);
    if (!isset($headers['authorization'])) {
        return null;
    }

    return trim(str_replace('Bearer', '', $headers['authorization']));
}

$authenticate = function ($request, $handler) {
    global $jwt_secret;
    $token = getBearerToken($request->getHeaderLine('Authorization'));
    if (!$token) {
        $response = new Psr7Response();
        $response->getBody()->write(json_encode(['error' => 'Token required']));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }

    try {
        // Validate the token
        $decoded = JWT::decode($token, new Key($jwt_secret, 'HS256'));

        // Proceed to the next middleware
        return $handler->handle($request);
    } catch (\Exception $e) {
        $response = new Psr7Response();
        $response->getBody()->write(json_encode(['error' => 'Invalid token', 'e' => $e->getMessage()]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
};

// Connect to database
$db = new PDO('mysql:host=localhost;dbname=sterry', 'root', '');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$app->get('/', function (Request $request, Response $response, $args) {
    $response->getBody()->write("Hello world!");
    return $response;
});

// Create a post
$app->post('/posts', function ($request, $response) {
    global $db; // access global $db
    $data = $request->getParsedBody();
    $validator = v::key('title', v::stringType()->notEmpty())
        ->key('content', v::stringType()->notEmpty())
        ->key('author_id', v::intVal()->notEmpty());

    try {
        $validator->assert($data);
    } catch (NestedValidationException $e) {
        $response->getBody()->write(json_encode($e->getMessages()));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }
    $sql = "INSERT INTO posts (title, content, author_id) 
            VALUES (:title, :content, :author_id)";

    try {
        $stmt = $db->prepare($sql);
        $stmt->execute([
            ':title' => $data['title'],
            ':content' => $data['content'],
            ':author_id' => $data['author_id']
        ]);
    } catch (PDOException $e) {
        echo $e;
        return $response->withStatus(500);
    }

    return $response->withStatus(201);
})->add($authenticate);

// Read - Get all posts
$app->get('/posts', function ($request, $response) {
    global $db; // access global $db
    $sql = "SELECT * FROM posts";

    try {
        $stmt = $db->query($sql);
        $posts = $stmt->fetchAll();
    } catch (PDOException $e) {
        return $response->withStatus(500);
    }
    $payload = json_encode($posts);
    $response->getBody()->write($payload);
    return $response
        ->withHeader('Content-Type', 'application/json');
})->add($authenticate);

// Read - Get single post 
$app->get('/posts/{id}', function ($request, $response, $args) {
    global $db; // access global $db

    $id = $args['id'];

    $sql = "SELECT * FROM posts WHERE id = :id";

    try {
        $stmt = $db->prepare($sql);
        $stmt->execute([':id' => $id]);
        $post = $stmt->fetch();
    } catch (PDOException $e) {
        return $response->withStatus(500);
    }

    $payload = json_encode($post);
    $response->getBody()->write($payload);
    return $response->withHeader('Content-Type', 'application/json');
})->add($authenticate);

// Update a post
$app->put('/posts/{id}', function ($request, $response, $args) {
    global $db; // access global $db
    $id = $args['id'];
    $data = $request->getParsedBody();
    $update_string = '';

    // Validate input
    $validator = v::key('title', v::optional(v::stringType()->notEmpty()))
        ->key('content', v::optional(v::stringType()->notEmpty()));
    // var_dump($validator);die;

    try {
        $validator->assert($data);
    } catch (NestedValidationException $e) {
        $response->getBody()->write(json_encode($e->getMessages()));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    if ($data['title']) {
        $update_string .= "title = '" . $data['title'] . "' ";
    }
    if ($data['title'] && $data['content']) {
        $update_string .= ", ";
    }
    if ($data['content']) {
        $update_string .= "content = '" . $data['content'] . "' ";
    }

    $sql = "UPDATE posts 
            SET " . $update_string .
        "WHERE id = :id";
    echo $sql . '\n';
    try {
        $stmt = $db->prepare($sql);
        $stmt->execute([
            ':id' => $id
        ]);
    } catch (PDOException $e) {
        echo $e;
        return $response->withStatus(500);
    }

    return $response->withStatus(200);
})->add($authenticate);

// Delete a post
$app->delete('/posts/{id}', function ($request, $response, $args) {
    global $db; // access global $db
    $id = $args['id'];

    $sql = "DELETE FROM posts WHERE id = :id";

    try {
        $stmt = $db->prepare($sql);
        $stmt->execute([':id' => $id]);
    } catch (PDOException $e) {
        return $response->withStatus(500);
    }

    return $response->withStatus(200);
})->add($authenticate);

// Login route
$app->post('/login', function ($request, $response) {
    global $jwt_secret; // access global $jwt_secret
    // Fetch user by email
    // Get post data
    $data = $request->getParsedBody();

    // Connect to database
    $db = new mysqli('localhost', 'root', '', 'sterry');

    // Query database
    $sql = "SELECT * FROM users WHERE email = ?";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('s', $data['email']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    // Verify password
    if ($user && password_verify($data['password'], $user['password'])) {

        // Generate JWT payload
        $payload = [
            'sub' => $user['id'],
            'iat' => time(),
            'exp' => time() + (7 * 24 * 60 * 60)
        ];

        // Encode JWT token
        $token = JWT::encode($payload, $jwt_secret, 'HS256');
        $payload = json_encode([
            'token' => $token
        ]);
        $response->getBody()->write($payload);
        return $response
            ->withHeader('Content-Type', 'application/json');
    } else {
        // Invalid credentials
        return $response->withStatus(401);
    }
});

$app->run();
