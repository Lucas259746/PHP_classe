<?php

class User
{
    private PDO $db;

    public function __construct()
    {
        $this->db = new PDO(
            "mysql:host=localhost;dbname=classes;charset=utf8",
            "root",
            "",
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]
        );
    }

    public function register(string $login, string $password, string $email, string $firstname, string $lastname): bool
    {
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $this->db->prepare("
            INSERT INTO utilisateurs (login, password, email, firstname, lastname)
            VALUES (:login, :password, :email, :firstname, :lastname)
        ");

        return $stmt->execute([
            'login' => $login,
            'password' => $hash,
            'email' => $email,
            'firstname' => $firstname,
            'lastname' => $lastname
        ]);
    }

    public function connect(string $login, string $password): bool
    {
        $stmt = $this->db->prepare("SELECT * FROM utilisateurs WHERE login = :login");
        $stmt->execute(['login' => $login]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user'] = $user;
            return true;
        }

        return false;
    }

    public function update(string $login, string $password, string $email, string $firstname, string $lastname, $id): bool
    {
        $id = (int) $id;

        if (!empty($password)) {
            $password = password_hash($password, PASSWORD_DEFAULT);
            $sql = "UPDATE utilisateurs 
                SET login=:login, password=:password, email=:email, firstname=:firstname, lastname=:lastname 
                WHERE id=:id";
            $params = [
                'login' => $login,
                'password' => $password,
                'email' => $email,
                'firstname' => $firstname,
                'lastname' => $lastname,
                'id' => $id
            ];
        } else {
            $sql = "UPDATE utilisateurs 
                SET login=:login, email=:email, firstname=:firstname, lastname=:lastname 
                WHERE id=:id";
            $params = [
                'login' => $login,
                'email' => $email,
                'firstname' => $firstname,
                'lastname' => $lastname,
                'id' => $id
            ];
        }

        $stmt = $this->db->prepare($sql);
        $result = $stmt->execute($params);

        if (isset($_SESSION['user']) && (int)$_SESSION['user']['id'] === $id) {
            $_SESSION['user'] = $this->getUserById($id);
        }

        return $result;
    }

    public function delete(): bool
    {
        if (!isset($_SESSION['user'])) {
            return false;
        }

        $stmt = $this->db->prepare("DELETE FROM utilisateurs WHERE id = :id");
        $result = $stmt->execute(['id' => $_SESSION['user']['id']]);

        $this->disconnect();
        return $result;
    }

    public function disconnect(): void
    {
        unset($_SESSION['user']);
    }

    public function getAllInfos(): array
    {
        return $_SESSION['user'] ?? ['id' => 0];
    }

    private function getUserById(int $id): array
    {
        $stmt = $this->db->prepare("SELECT * FROM utilisateurs WHERE id = :id");
        $stmt->execute(['id' => $id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}
