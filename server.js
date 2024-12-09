const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = 3001;

// Configuración de la base de datos
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

const pool = mysql.createPool(dbConfig);

// Configuración de middleware
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'tu_secreto_aqui',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'HTML pagina')));

// Redirigir TODAS las rutas al login si no hay sesión
app.use((req, res, next) => {
    // Rutas que siempre deben ser accesibles
    const publicPaths = ['/login.html', '/login', '/css', '/js', '/images'];
    const isPublicPath = publicPaths.some(path => req.path.startsWith(path));

    if (isPublicPath) {
        return next();
    }

    if (!req.session.usuario) {
        if (req.path !== '/login.html') {
            return res.redirect('/login.html');
        }
    }
    next();
});

// Ruta raíz
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// Middleware básico
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'tu_secreto_aqui',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Middleware para verificar autenticación
const checkAuth = (req, res, next) => {
    // Rutas que no requieren autenticación
    const publicPaths = ['/login.html', '/login', '/css', '/js', '/images'];
    if (publicPaths.some(path => req.path.startsWith(path))) {
        return next();
    }
    
    // Si no está autenticado y no es una ruta pública, redirige al login
    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }
    
    next();
};

// Aplicar verificación de autenticación a todas las rutas
app.use(checkAuth);

// Ruta principal - siempre redirige al login si no está autenticado
app.get('/', (req, res) => {
    if (!req.session.usuario) {
        res.redirect('/login.html');
    } else {
        res.redirect('/index.html');
    }
});

// Middleware de autenticación
const isAuthenticated = (req, res, next) => {
    if (req.session.usuario) {
        next();
    } else {
        res.redirect('/login.html');
    }
};

// Middleware para verificar rol de profesor
const requireProfesor = (req, res, next) => {
    console.log('Verificando rol de profesor:', req.session.usuario);
    if (!req.session.usuario || req.session.usuario.role !== 'profesor') {
        return res.status(403).json({
            success: false,
            message: 'Acceso denegado. Se requiere rol de profesor.'
        });
    }
    next();
};

// Rutas de autenticación
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        const [rows] = await pool.execute(
            'SELECT * FROM usuarios WHERE username = ? AND password = ? AND role = ?',
            [username, password, role]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Credenciales incorrectas'
            });
        }

        const usuario = rows[0];
        req.session.usuario = {
            id: usuario.id,
            username: usuario.username,
            role: usuario.role
        };

        res.json({
            success: true,
            message: 'Login exitoso',
            role: usuario.role,
            redirectTo: '/index.html'
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({
            success: false,
            message: 'Error en el servidor'
        });
    }
});

// Ruta de registro
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email, role } = req.body;
        
        // Verificar si el usuario ya existe
        const [existingUsers] = await pool.execute(
            'SELECT * FROM usuarios WHERE username = ?',
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'El usuario ya existe'
            });
        }

        // Insertar nuevo usuario
        const [result] = await pool.execute(
            'INSERT INTO usuarios (username, password, email, role) VALUES (?, ?, ?, ?)',
            [username, password, email, role]
        );

        req.session.usuario = {
            id: result.insertId,
            username,
            role
        };

        res.json({
            success: true,
            message: 'Usuario registrado exitosamente',
            redirectTo: '/index.html'
        });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({
            success: false,
            message: 'Error en el servidor'
        });
    }
});

// Endpoint para verificar si existe un correo
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM usuarios WHERE email = ?',
            [email]
        );
        
        res.json({ exists: rows.length > 0 });
    } catch (error) {
        console.error('Error al verificar email:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al verificar el correo electrónico' 
        });
    }
});

// Endpoint para registro de usuarios
app.post('/register', async (req, res) => {
    const { nombre, apellido, email, password, role } = req.body;

    try {
        // Verificar si el correo ya existe
        const [existingUser] = await pool.execute(
            'SELECT * FROM usuarios WHERE email = ?',
            [email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Este correo ya está registrado'
            });
        }

        // Insertar en la tabla usuarios
        const [result] = await pool.execute(
            'INSERT INTO usuarios (nombre, apellido, email, password, role) VALUES (?, ?, ?, ?, ?)',
            [nombre, apellido, email, password, role]
        );

        const userId = result.insertId;

        // Insertar en la tabla específica según el rol
        let roleTableQuery = '';
        switch (role) {
            case 'estudiante':
                roleTableQuery = 'INSERT INTO estudiantes (id_usuario, nombre, apellido) VALUES (?, ?, ?)';
                break;
            case 'profesor':
                roleTableQuery = 'INSERT INTO profesores (id_usuario, nombre, apellido) VALUES (?, ?, ?)';
                break;
            case 'admin':
                roleTableQuery = 'INSERT INTO administradores (id_usuario, nombre, apellido) VALUES (?, ?, ?)';
                break;
        }

        if (roleTableQuery) {
            await pool.execute(roleTableQuery, [userId, nombre, apellido]);
        }

        // Crear sesión para el usuario
        req.session.usuario = {
            id: userId,
            nombre,
            apellido,
            email,
            role
        };

        res.json({
            success: true,
            message: 'Usuario registrado exitosamente',
            redirectTo: '/index.html'
        });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({
            success: false,
            message: 'Error al registrar el usuario'
        });
    }
});

// Ruta para obtener notas
app.get('/api/notas/:alumnoId', async (req, res) => {
    try {
        const [notas] = await pool.execute(
            'SELECT * FROM boletinnotas WHERE alumno_id = ?',
            [req.params.alumnoId]
        );
        res.json(notas);
    } catch (error) {
        console.error('Error al obtener notas:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener notas'
        });
    }
});

// Ruta para agregar notas (solo profesores)
app.post('/api/notas', requireProfesor, async (req, res) => {
    console.log('Recibida petición para agregar nota');
    console.log('Body completo:', JSON.stringify(req.body, null, 2));

    try {
        const notas = req.body;
        
        if (!Array.isArray(notas)) {
            return res.status(400).json({
                success: false,
                message: 'El formato de los datos es incorrecto. Se espera un array de notas.'
            });
        }

        // Verificar cada nota
        for (const nota of notas) {
            if (!nota.alumnoId || !nota.materiaId || !nota.nota || !nota.periodo) {
                return res.status(400).json({
                    success: false,
                    message: 'Cada nota debe tener alumnoId, materiaId, nota y periodo',
                    notaInvalida: nota
                });
            }
        }

        // Insertar todas las notas
        const resultados = [];
        for (const nota of notas) {
            const [result] = await pool.execute(
                'INSERT INTO boletinnotas (alumno_id, materia_id, nota, periodo, fecha) VALUES (?, ?, ?, ?, NOW())',
                [nota.alumnoId, nota.materiaId, nota.nota, nota.periodo]
            );
            resultados.push(result);
        }

        console.log('Notas agregadas exitosamente:', resultados);

        res.json({
            success: true,
            message: 'Notas agregadas exitosamente',
            resultados: resultados
        });
    } catch (error) {
        console.error('Error detallado al agregar notas:', {
            message: error.message,
            stack: error.stack,
            sqlMessage: error.sqlMessage,
            sqlState: error.sqlState,
            code: error.code
        });

        res.status(500).json({
            success: false,
            message: 'Error al agregar notas',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Ruta para buscar notas por nombre de estudiante
app.get('/api/notas/buscar', async (req, res) => {
    try {
        const nombreEstudiante = req.query.nombre;
        console.log('Buscando notas para estudiante:', nombreEstudiante);

        if (!nombreEstudiante) {
            return res.status(400).json({
                success: false,
                message: 'Debe proporcionar un nombre de estudiante'
            });
        }

        // Mostrar la consulta SQL que se va a ejecutar
        const consultaSQL = 'SELECT id, nombre, apellido FROM usuarios WHERE CONCAT(nombre, " ", apellido) LIKE ? AND role = "estudiante"';
        const parametro = `%${nombreEstudiante}%`;
        console.log('Consulta SQL:', consultaSQL);
        console.log('Parámetro:', parametro);

        // Primero buscamos el estudiante
        const [estudiantes] = await pool.execute(consultaSQL, [parametro]);
        
        console.log('Estudiantes encontrados:', estudiantes);

        if (estudiantes.length === 0) {
            return res.json({
                success: true,
                notas: [],
                message: 'No se encontró el estudiante'
            });
        }

        const estudianteId = estudiantes[0].id;

        // Consulta para las notas
        const consultaNotas = `
            SELECT 
                bn.*,
                m.nombre as materia_nombre,
                u.nombre as nombre_estudiante,
                u.apellido as apellido_estudiante
            FROM boletinnotas bn 
            JOIN materias m ON bn.materia_id = m.id 
            JOIN usuarios u ON bn.alumno_id = u.id
            WHERE bn.alumno_id = ?`;
        
        console.log('Consulta notas:', consultaNotas);
        console.log('ID estudiante:', estudianteId);

        const [notas] = await pool.execute(consultaNotas, [estudianteId]);
        
        console.log('Notas encontradas:', notas);

        res.json({
            success: true,
            estudiante: {
                id: estudiantes[0].id,
                nombre: estudiantes[0].nombre,
                apellido: estudiantes[0].apellido
            },
            notas: notas
        });
    } catch (error) {
        console.error('Error detallado al buscar notas:', {
            message: error.message,
            stack: error.stack,
            sqlMessage: error.sqlMessage,
            sqlState: error.sqlState,
            code: error.code
        });

        res.status(500).json({
            success: false,
            message: 'Error al buscar notas',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Ruta de login
app.post('/login', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const [rows] = await pool.query(
            'SELECT * FROM usuarios WHERE email = ? AND password = ? AND role = ?',
            [email, password, role]
        );
        
        if (rows.length > 0) {
            req.session.usuario = rows[0];
            res.json({ success: true });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Credenciales incorrectas' 
            });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor' 
        });
    }
});

// Ruta de logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`
    ===============================================
    🚀 Servidor iniciado exitosamente
    📁 Archivos servidos desde: ${path.join(__dirname, 'HTML pagina')}
    🌐 Accede a: http://localhost:${PORT}
    ⚠️  Serás redirigido al login si no has iniciado sesión
    ===============================================
    `);
});
