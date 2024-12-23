<?php
session_start();
include('../includes/db.php');

if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password']; // Password yang dimasukkan oleh pengguna

    // Query untuk mengambil data user berdasarkan username
    $sql = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();

        // Cek apakah password cocok menggunakan metode hash baru
        if (password_verify($password, $user['password'])) { 
            // Password cocok dengan hash
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role'];
            
            // Redirect berdasarkan role
            if ($_SESSION['role'] === 'siswa') {
                header('Location: dashboard_siswa.php');
            } elseif ($_SESSION['role'] === 'petugas') {
                header('Location: dashboard_petugas.php');
            } elseif ($_SESSION['role'] === 'admin') {
                header('Location: dashboard_admin.php');
            }
            exit;
        } 
        // Cek fallback: password cocok dengan metode lama (plaintext)
        elseif ($password === $user['password']) { 
            // Password cocok dengan plaintext
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role'];

            // Perbarui password di database ke format hash baru untuk keamanan
            $new_hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $update_sql = "UPDATE users SET password = ? WHERE id = ?";
            $update_stmt = $conn->prepare($update_sql);
            $update_stmt->bind_param("si", $new_hashed_password, $user['id']);
            $update_stmt->execute();

            // Redirect berdasarkan role
            if ($_SESSION['role'] === 'siswa') {
                header('Location: dashboard_siswa.php');
            } elseif ($_SESSION['role'] === 'petugas') {
                header('Location: dashboard_petugas.php');
            } elseif ($_SESSION['role'] === 'admin') {
                header('Location: dashboard_admin.php');
            }
            exit;
        } else {
            // Password tidak cocok
            echo "<div class='alert alert-danger text-center'>Username or password is incorrect.</div>";
        }
    } else {
        // Username tidak ditemukan
        echo "<div class='alert alert-danger text-center'>Username or password is incorrect.</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: url('https://source.unsplash.com/1600x900/?library,books') no-repeat center center fixed;
            background-size: cover;
            height: 100vh;
        }
        .container {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100%;
        }
        .login-card {
            background-color: rgba(255, 255, 255, 0.8);
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }
        h2 {
            text-align: center;
            margin-bottom: 30px;
        }
        .btn {
            border-radius: 50px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-card">
            <h2><i class="fas fa-user-lock"></i> Login</h2>
            <form method="POST">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100" name="login"><i class="fas fa-sign-in-alt"></i> Login</button>
            </form>
        </div>
    </div>

    <!-- Bootstrap JS and FontAwesome for icons -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
</body>
</html>
