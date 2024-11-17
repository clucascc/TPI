<?php
// Configuración de conexión a la base de datos
$host = "localhost";
$user = "root";
$password = ""; // Dejar vacío para XAMPP
$database = "programación"; // Nombre de tu base de datos

// Crear conexión
$conn = new mysqli($host, $user, $password, $database);

// Verificar conexión
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

// Procesar datos enviados por el formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $username = $_POST['username'];
    $password = $_POST['password'];
    $role = $_POST['role'];

    // Encriptar contraseña
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Preparar consulta SQL
    $stmt = $conn->prepare("INSERT INTO usuarios (email, username, password, role) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $email, $username, $hashedPassword, $role);

    // Ejecutar y verificar
    if ($stmt->execute()) {
        echo "Usuario registrado con éxito.";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Cerrar conexión
    $stmt->close();
    $conn->close();
}
?>
