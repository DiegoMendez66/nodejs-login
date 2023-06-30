const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine','ejs');
app.use(session({
  secret: 'mysecretkey',
  resave: true,
  saveUninitialized: true
}));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '123456',
  database: 'bdpractica4'
});

connection.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database!');
});

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});

app.get('/', (req, res) => {
    res.render('login', { message: '' });
  });
  
app.get('/login', (req, res) => {
    res.render('login', { message: '' });
  });
  
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
      connection.query('SELECT * FROM users WHERE username = ?', [username], (error, results, fields) => {
        if (results.length > 0) {
          bcrypt.compare(password, results[0].password, (err, result) => {
            if (result === true) {
              req.session.loggedin = true;
              req.session.username = username;
              res.redirect('/home');
            } else {
              res.render('login', { message: 'Nombre de usuario y/o contraseña no válidos' });
            }
          });
        } else {
          res.render('login', { message: 'Nombre de usuario y/o contraseña no válidos' });
        }
      });
    } else {
      res.render('login', { message: 'Nombre de usuario y/o contraseña no válidos' });
    }
});
  
app.get('/register', (req, res) => {
    res.render('register', {message: '' });
});
  
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
      bcrypt.hash(password, 10, (err, hash) => {
        connection.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (error, results, fields) => {
          if (error) {
            res.render('register', { message: 'Usuario ya existente!' });
          } else {
            req.session.loggedin = true;
            req.session.username = username;
            res.redirect('/home');
          }
        });
      });
    } else {
      res.render('register', { message: 'Ingresar nombre de usuario y contraseña!' });
    }
});
  
app.get('/home', (req, res) => {
    if (req.session.loggedin) {
      res.render('home', { username: req.session.username });
    } else {
      res.redirect('/login');
    }
});
  
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Ruta para mostrar la página de configuración de usuario
app.get('/configuracion', (req, res) => {
    res.render('configuracion', { message: '' });
  });
  
// Ruta para procesar el formulario de configuración de usuario
app.post('/configuracion', (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.session.username;
  
    // Verificar si se ingresó la contraseña actual y la nueva contraseña
    if (oldPassword && newPassword) {
      // Obtener la contraseña actual almacenada en la base de datos
      connection.query('SELECT password FROM users WHERE username = ?', [username], (error, results, fields) => {
        if (error) {
          res.render('configuracion', { message: 'Error al recuperar la contraseña actual' });
        } else {
          const passwordHash = results[0].password;
          // Verificar si la contraseña actual ingresada es correcta
          bcrypt.compare(oldPassword, passwordHash, (err, isMatch) => {
            if (err) {
              res.render('configuracion', { message: 'Error al comparar contraseñas' });
            } else if (isMatch) {
              // Cifrar la nueva contraseña
              bcrypt.hash(newPassword, 10, (err, hash) => {
                // Actualizar la contraseña en la base de datos
                connection.query('UPDATE users SET password = ? WHERE username = ?', [hash, username], (error, results, fields) => {
                  if (error) {
                    res.render('configuracion', { message: 'Error al actualizar la contraseña' });
                  } else {
                    res.render('configuracion', { message: 'Contraseña actualizada exitosamente' });
                  }
                });
              });
            } else {
            res.render('configuracion', { message: 'La contraseña actual no es correcta' });
            }
          });
        }
      });
    } else {
    res.render('configuracion', { message: 'Ingresar la contraseña actual y la nueva contraseña' });
    }
});