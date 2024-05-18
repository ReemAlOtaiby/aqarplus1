const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Import bcryptjs for password hashing
const nodemailer = require('nodemailer');
const app = express();
const jwt = require('jsonwebtoken');
const port = 3017;
app.use(express.json());
app.use(cors());

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'irshaad'
});
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your_email@gmail.com',
    pass: 'your_email_password'
  }
});
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'HussainALibukhari12434itsecurityengineer', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ' + err.stack);
    return;
  }
  console.log('Connected to MySQL as id ' + connection.threadId);
});

app.post('/users', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

    const sql = 'INSERT INTO register (name, email, password) VALUES (?, ?, ?)';
    const values = [name, email, hashedPassword];

    connection.query(sql, values, (error, results, fields) => {
      if (error) {
        console.error('Error inserting data: ' + error.stack);
        res.status(500).send('Error inserting data');
        return;
      }
      console.log('Inserted data successfully');
      res.status(200).send('Inserted data successfully');
    });
  } catch (error) {
    console.error('Error hashing password: ' + error);
    res.status(500).send('Error hashing password');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  connection.query('SELECT * FROM register WHERE email = ?', [email], async (error, results, fields) => {
    if (error) {
      console.error('Error retrieving user data: ' + error.stack);
      res.status(500).send('Error retrieving user data');
      return;
    }

    if (results.length === 0) {
      res.status(401).send('User not found');
      return;
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password); // Compare hashed password

    if (!passwordMatch) {
      res.status(401).send('Invalid password');
      return;
    }

    // Generate JWT
    const token = jwt.sign({ userId: user.id }, 'HussainALibukhari12434itsecurityengineer', { expiresIn: '1h' });

    res.status(200).json({ token });
  });
});
app.post('/properties', (req, res) => {
  const { name, price, description, image } = req.body;
  const sql = 'INSERT INTO property (name, price, description, image) VALUES (?, ?, ?, ?)';
  connection.query(sql, [name, price, description, image], (err, result) => {
    if (err) {
      console.error('Error inserting property:', err);
      res.status(500).send('Error inserting property');
    } else {
      console.log('Property inserted successfully');
      res.status(201).send('Property inserted successfully');
    }
  });
});


app.put('/profile', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { email } = req.body;

  try {
    // Update the user's email in the database
    await connection.query('UPDATE register SET email = ? WHERE id = ?', [email, userId]);

    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  connection.query('SELECT email, password FROM register WHERE id = ?', [userId], (error, results, fields) => {
    if (error) {
      console.error('Error retrieving user profile:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userProfile = {
      email: results[0].email,
      password: results[0].password,
      // Add more profile details here if needed
    };
    res.status(200).json(userProfile);
  });
});
app.post('/add_property', (req, res) => {
  const { property_name, price, description, owner_name, owner_contact, image_url } = req.body;
  const sql = `INSERT INTO Properties (property_name, price, description, owner_name, owner_contact, image_url) 
               VALUES (?, ?, ?, ?, ?, ?)`;
  connection.query(sql, [property_name, price, description, owner_name, owner_contact, image_url], (err, result) => {
      if (err) {
          console.error('Error inserting property into MySQL database:', err);
          return res.status(400).json({ error: 'An error occurred while adding the property' });
      }
      console.log('Property added to MySQL database');
      res.status(201).json({ message: 'Property added successfully' });
  });
})
app.get('/properties', (req, res) => {
  const sql = 'SELECT * FROM Properties';
  connection.query(sql, (err, results) => {
      if (err) {
          console.error('Error fetching properties from MySQL database:', err);
          return res.status(500).json({ error: 'An error occurred while fetching properties' });
      }
      res.json(results);
  });
});


app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
