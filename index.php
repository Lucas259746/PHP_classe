<?php

declare(strict_types=1);

require_once 'user.php';

if (session_status() === PHP_SESSION_NONE) session_start();

$userObj = new User();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Register
    if (isset($_POST['register'], $_POST['login'], $_POST['password'], $_POST['email'], $_POST['firstname'], $_POST['lastname'])) {
        $registerResult = $userObj->register($_POST['login'], $_POST['password'], $_POST['email'], $_POST['firstname'], $_POST['lastname']);
    } else {
        // Connect
        $userObj->connect((string)$_POST['oldLogin'], (string)$_POST['password']);
    }

    // Update
    if (isset($_POST['update'], $_POST['login'], $_POST['password'], $_POST['email'], $_POST['firstname'], $_POST['lastname'], $_POST['id'])) {
        $updateResult = $userObj->update($_POST['login'], $_POST['password'], $_POST['email'], $_POST['firstname'], $_POST['lastname'], $_POST['id']);
    }

    // Delete
    if (isset($_POST['delete']) && isset($_POST['id'])) {
        $userObj->delete();
    }

    // Disconnect
    if (isset($_POST['disconnect'])) {
        $userObj->disconnect();
    }
}

$mysqli = new PDO("mysql:host=localhost;dbname=classes", "root", "");
$stmt = $mysqli->prepare("SELECT * FROM utilisateurs");
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$userInfos = $userObj->getAllInfos();

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>

<body>
    <p>Id de l'utilisateur connecté:<?= (int)$userInfos['id'] ?> </p>
    <form method="post" action="">
        <input type="text" name="login" placeholder="Login" required>
        <input type="text" name="email" placeholder="Email" required>
        <input type="text" name="firstname" placeholder="First Name" required>
        <input type="text" name="lastname" placeholder="Last Name" required>
        <input type="text" name="password" placeholder="Password" required>
        <input type="hidden" name="register" value="true">
        <button type="submit">Register</button>
        <br /><br />
    </form>
    <?php foreach ($users as $u) : ?>
        <form method="post" action="" style="display: inline-block;">
            <input type="hidden" name="id" value="<?= $u['id'] ?>">
            <input type="hidden" name="oldLogin" value="<?= $u['login'] ?>">
            <input type="text" name="login" value="<?= $u['login'] ?>" required>
            <input type="text" name="email" value="<?= $u['email'] ?>" required>
            <input type="text" name="firstname" value="<?= $u['firstname'] ?>" required>
            <input type="text" name="lastname" value="<?= $u['lastname'] ?>" required>
            <input type="text" name="password" placeholder="Password">
            <?= (($userInfos['id']) === (int)$u['id']) ? '<button type="submit" name="update" value="true">Update</button><button type="submit" name="delete" value="true">Delete</button><button type="submit" name="disconnect" value="' . $u['id'] . '">Disconect</button>' : '<button type="submit" name="connect" value="true"<button>Connect</button>' ?>
        </form>
    <?php endforeach; ?>
</body>

</html>