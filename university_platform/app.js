// Importo módulos
const express = require('express');
const mysql = require('mysql');
const util = require('util');
const jwt = require('jsonwebtoken');
const unless = require('express-unless');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { response } = require('express');

const app = express();

app.use(express.json());
app.use(cors());

const PORT = process.env.PORT ? process.env.PORT : 3000; // Verifica si hay un puerto disponible, sino usa el 3000.

// Conexión con la base de datos
const conexion = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'university'
});

// Verifico conexión
conexion.connect((error) => {
    if (error) {
        throw {
            message: 'Error en la conexión con la base de datos',
            status: 500
        }
    }

    console.log('Se estableció la conexión con la base de datos.')
});

const query = util.promisify(conexion.query).bind(conexion);

// Middleware, ejecuta primero el registro o login antes de llevar al cliente a la ruta solicitada. 
//Luego automáticamente lo lleva a la ruta
const auth = (req, res, next) => {
    try{
        let token = req.headers['authorization'];

        if (!token) {
            throw{
                message: 'No estas logueado',
                status: 400
            }
        }

        token = token.replace('Bearer ', '');

        jwt.verify(token, 'Secret', (err, user) => {
            if (err) {
                throw {
                    message: 'Token inválido.',
                    status: 400
                }
            }
        });

        next();

    } catch(e){
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
};

auth.unless = unless;

app.use(
    auth.unless({
        path: [
            {url: '/login', methods: ['POST']},
            {url: '/registro', methods: ['POST']},
        ],
    }),
);

// REGISTRO
app.post('/registro', async (req, res) => {
    try {
        let testRegex = /[a-z]/gi; 

        if (!req.body.usuario || !req.body.clave || !req.body.email || !testRegex.test(req.body.usuario) || !testRegex.test(req.body.clave) || !testRegex.test(req.body.email)) {
            throw {
                message: 'No enviaste todos los datos necesarios',
                status: 400
            }
        }

        const validacionUsuario = await query('SELECT * FROM usuario WHERE usuario = ?', [req.body.usuario]);

        if (validacionUsuario.length > 0) {
            throw {
                message: 'El usuario ya existe',
                status: 400
            }
        }
        // Si esta todo bien, encripto la clave
        const claveEncriptada = await bcrypt.hash(req.body.clave, 10);

        // Guardar el usuario con la clave encriptada
        const usuario = {
            usuario: req.body.usuario,
            clave: claveEncriptada,
            email: req.body.email
        };

        await query('INSERT INTO usuario (usuario, clave, email) values (?,?,?)', [usuario.usuario, usuario.clave, usuario.email]);

        res.send({message: 'Se registro correctamente'});

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// LOGIN
app.post('/login', async (req, res) => {
    try {
        let testRegex = /[a-z]/gi; 

        if (!req.body.usuario || !req.body.clave || !testRegex.test(req.body.usuario) || !testRegex.test(req.body.clave)) {
            throw {
                message: 'No enviaste los datos necesarios',
                status: 400
            }
        }

        const usuario = await query('SELECT * FROM usuario WHERE usuario = ?', [req.body.usuario]);

        //Verifico si existe el usuario.
        if (usuario.length == 0) {
            throw {
                message: 'Usuario inocorrecto',
                status: 404
            }
        }

        const claveCoincide = bcrypt.compareSync(req.body.clave, usuario[0].clave);

        //Verifico si la clave coincide.
        if (!claveCoincide) {
            throw {
                message: 'Password incorrecto',
                status: 404
            }
        }
        // Datos de la sesión
        const tokenData = {
            usuario: usuario[0].usuario,
            email: usuario[0].email,
            user_id: usuario[0].id
        }

        const token = jwt.sign(tokenData, 'Secret', {
            expiresIn: 60 * 60 * 24, 
        });

        res.send({ token });
        
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
})

/**
 * Ruta --> CARRERA
 */
// MOSTRAR TODAS LAS CARRERAS
app.get('/api/carrera', async (req, res) => {
    try {
        let response = await query('SELECT * FROM carrera');
        
        if (response.length == 0) {
            throw {
                message: 'No hay ninguna carrera para mostrar.',
                status: 404
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e){
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
})

// MOSTRAR UNA CARRERA
app.get('/api/carrera/:id', async (req, res) => {
    try{
        let response = await query('SELECT * FROM carrera WHERE id = ?', [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'La carrera no existe.'
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error('No encontrado.');
        res.status(404).send({"Error": e.message}); 
    }
});

// AGREGAR CARRERA
app.post('/api/carrera', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi;  

        if (!req.body.nombre || !testRegex.test(req.body.nombre)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        const nombre = req.body.nombre.toUpperCase();
        let response = await query('SELECT id FROM carrera WHERE nombre = ?', [nombre]);

        if (response.length > 0) {
            throw {
                message: 'Ese nombre de carrera ya existe.',
                status: 404
            }
        }

        let requery = 'INSERT INTO carrera (nombre) VALUE (?)';

        response = await query(requery, [nombre]);

        res.send({"respuesta": response});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// MODIFICAR UNA CARRERA
app.put('/api/carrera/:id', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi; 

        if (!req.body.nombre || !testRegex.test(req.body.nombre)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        let requery = 'SELECT nombre FROM carrera WHERE id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length == 0){
            throw {
                message: 'No se encuentra esa carrera.',
                status: 404
            }
        }

        requery = 'UPDATE carrera SET nombre = ? WHERE id = ?';

        response = await query(requery, [req.body.nombre, req.params.id]);

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// ELIMINAR UNA CARRERA
app.delete('/api/carrera/:id', async (req, res) => {
    try{
        let requery = 'SELECT * FROM alumno WHERE carrera_id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length > 0) {
            throw {
                message: 'La carrera tiene alumnos asociados. NO se puede ELIMINAR.',
                status: 400
            }
        }

        requery = 'SELECT * FROM carrera WHERE id = ?';

        response = await query(requery, [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'No existe la carrera indicada.',
                status: 404
            }
        }

        requery = 'DELETE FROM carrera WHERE id = ?';

        response = await query(requery, [req.params.id]);

        res.send({"respuesta": 'La carrera se eliminó correctamente'});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

/**
 * Ruta --> MATERIA
 */
// MOSTRAR TODAS LAS MATERIAS
app.get('/api/materia', async (req, res) => {
    try {
        let response = await query('SELECT * FROM materia');
        
        if (response.length == 0) {
            throw {
                message: 'No hay ninguna materia para mostrar.',
                status: 404
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e){
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
})

// MOSTRAR UNA MATERIA
app.get('/api/materia/:id', async (req, res) => {
    try{
        let response = await query('SELECT * FROM materia WHERE id = ?', [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'La materia no existe.'
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error('No encontrado.');
        res.status(404).send({"Error": e.message}); 
    }
});

// AGREGAR MATERIA
app.post('/api/materia', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi; 

        if (!req.body.nombre || !testRegex.test(req.body.nombre)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        const nombre = req.body.nombre.toUpperCase();
        let response = await query('SELECT id FROM materia WHERE nombre = ?', [nombre]);

        if (response.length > 0) {
            throw {
                message: 'Ese nombre de materia ya existe.',
                status: 404
            }
        }

        let requery = 'INSERT INTO materia (nombre) VALUE (?)';

        response = await query(requery, [nombre]);

        res.send({"respuesta": response});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// MODIFICAR UNA MATERIA
app.put('/api/materia/:id', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi; 

        if (!req.body.nombre || !testRegex.test(req.body.nombre)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        let requery = 'SELECT nombre FROM materia WHERE id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length == 0){
            throw {
                message: 'No se encuentra esa materia.',
                status: 404
            }
        }

        requery = 'UPDATE materia SET nombre = ? WHERE id = ?';

        response = await query(requery, [req.body.nombre, req.params.id]);

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// ELIMINAR UNA MATERIA
app.delete('/api/materia/:id', async (req, res) => {
    try{
        let requery = 'SELECT * FROM alumno WHERE materia_id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length > 0) {
            throw {
                message: 'La materia tiene alumnos asociados. NO se puede ELIMINAR.',
                status: 400
            }
        }

        requery = 'SELECT * FROM materia WHERE id = ?';

        response = await query(requery, [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'No existe la materia indicada.',
                status: 404
            }
        }

        requery = 'DELETE FROM materia WHERE id = ?';

        response = await query(requery, [req.params.id]);

        res.send({"respuesta": 'La materia se eliminó correctamente'});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});


/**
 * Ruta --> ALUMNO
 */

// MOSTRAR ALUMNOS
app.get('/api/alumno', async (req, res) => {
    try {
        let response = await query('SELECT * FROM alumno');
        
        if (response.length == 0) {
            throw {
                message: 'No hay ningún alumno para mostrar.',
                status: 404
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);


    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
})

// MOSTRAR UN ALUMNO
app.get('/api/alumno/:id', async (req, res) => {
    try{
        let response = await query('SELECT * FROM alumno WHERE id = ?', [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'El alumno no existe.'
            }
        }

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(404).send({"Error": e.message}); 
    }
});

// AGREGAR ALUMNO
app.post('/api/alumno', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi;

        if (!req.body.nombre || !req.body.apellido || !req.body.materia_id || !req.body.carrera_id || !testRegex.test(req.body.nombre) 
        || !testRegex.test(req.body.apellido)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        const materia_id = req.body.materia_id;
        const carrera_id = req.body.carrera_id;

        let requery = 'SELECT * FROM materia WHERE id = ?';

        let response = await query(requery, [req.body.materia_id]);

        if (response.length == 0) {
            throw {
                message: 'Esa materia no existe',
                status: 404
            }
        }

        requery = 'SELECT * FROM carrera WHERE id = ?';

        response = await query(requery, [req.body.carrera_id]);

        if (response.length == 0) {
            throw {
                message: 'Esa carrera no existe',
                status: 404
            }
        }

        const nombre = req.body.nombre.toUpperCase();
        const apellido = req.body.apellido.toUpperCase();

        requery = 'INSERT INTO alumno (nombre, apellido, materia_id, carrera_id) VALUE (?, ?, ?, ?)';

        response = await query(requery, [nombre, apellido, materia_id, carrera_id]);

        res.send({"respuesta": response});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// MODIFICAR UN ALUMNO
app.put('/api/alumno/:id', async (req, res) => {
    try{
        let testRegex = /[a-z]/gi;

        if (!req.body.nombre || !req.body.apellido || !req.body.materia_id || !req.body.carrera_id || !testRegex.test(req.body.nombre) 
        || !testRegex.test(req.body.apellido)) {
            throw {
                message: 'Faltan datos.',
                status: 400
            }
        }

        let requery = 'SELECT nombre FROM alumno WHERE id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length == 0){
            throw {
                message: 'No se encuentra ese alumno.',
                status: 404
            }
        }

        requery = 'UPDATE alumno SET nombre = ?, apellido = ?, materia_id = ?, carrera_id = ? WHERE id = ?';

        response = await query(requery, [req.body.nombre, req.body.apellido, req.body.materia_id, req.body.carrera_id, req.params.id]);

        res.json(response);
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);

    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});

// ELIMINAR UN ALUMNO
app.delete('/api/alumno/:id', async (req, res) => {
    try{
        let requery = 'SELECT * FROM alumno WHERE id = ?';

        let response = await query(requery, [req.params.id]);

        if (response.length == 0) {
            throw {
                message: 'No existe el alumno indicado.',
                status: 404
            }
        }

        requery = 'DELETE FROM alumno WHERE id = ?';

        response = await query(requery, [req.params.id]);

        res.send({"respuesta": 'El alumno se eliminó correctamente'});
        console.log('Operación realizada de manera correcta, sin errores.')
        res.status(200);
    
    } catch(e) {
        if (e.status == null) {
            res.status(500).send({"Error": "Error inesperado."}); 
        }

        console.error(e.message);
        res.status(e.status).send({"Error": e.message}); 
    }
});



//--------------------------------------------------------------------------------------------------------------------------------------
app.listen(PORT, () => {
    console.log('Aplicación corriendo en puerto ', PORT);
});