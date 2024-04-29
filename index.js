const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Datastore = require('nedb-promises');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
const PORT = 3000;


app.use(express.json());



const dbuser = new Datastore({ filename: 'user.db', autoload: true });
const dbnote = new Datastore({ filename: 'note.db', autoload: true });


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


app.post('/api/user/signup', async (req, res) => {
    try {
      const { username, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
  
        await dbuser.insert({ username, passwordHash: hashedPassword });
      res.status(201).json({ message: 'Skapade användare' });
    } catch (error) {
      res.status(500).json({ message: 'server fel' });
    }
  });


app.post('/api/user/login', async (req, res) => {
    try {
      const { username, password } = req.body;
  
      const user = await dbuser.findOne({ username });
      if (!user) {
        return res.status(401).json({ error: 'fel username' });
      }
  
      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        return res.status(401).json({ error: 'fel password' });
      }
  
      const accessToken  =  jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      res.json({ accessToken });
    } catch (error) {
      res.status(500).json({ error: 'Server fel' });
    }
  });


  app.get('/api/notes', authenticateToken, async (req, res) => {
    try {
      const notes = await dbnote.find({});
      res.json(notes);
    } catch (error) {
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });


app.post('/api/notes/add', authenticateToken, async (req, res) => {
    try {
      const { title, text } = req.body;
      const createdAt = new Date();
      const modifiedAt = createdAt;
      
      await dbnote.insert({ title, text, createdAt, modifiedAt });
      
      res.status(201).json({ message: 'Anteckning sparad' });
    } catch (error) {
      res.status(500).json({ error: 'Serverfel' });
    }
  });


app.put('/api/notes/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
      const { title, text } = req.body;
      const modifiedAt = new Date();
  
      const updatedNote = await dbnote.update({ _id: id }, { $set: { title, text, modifiedAt } });
  
      res.json({ message: 'Anteckning uppdaterad', updatedNote });
    } catch (error) {
      res.status(500).json({ error: 'Serverfel' });
    }
  });


app.delete('/api/notes/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
  
      const remove = await dbnote.remove({ _id: id });
  
      if (remove === 1) {
        res.json({ message: 'Anteckning borttagen' });
      } else {
        res.status(404).json({ error: 'Anteckning ej hittad' });
      }
    } catch (error) {
      res.status(500).json({ error: 'Serverfel' });
    }
  });

// Söka bland anteckningar
app.get("/api/notes/search", authenticateToken, async (req, res) => {
    const searchText = req.query.search;
    const regexObj = new RegExp(searchText);

    console.log("Regular Expression:", regexObj);
    
    try {
        const foundNotes = await dbnote.find({ title: regexObj });
        res.json({ results: foundNotes });
    } catch (err) {
      console.error("Database Error:", err); // Log any errors from dbnote.find() to consol
        res.status(500).send("Internal Server Error");
    }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});