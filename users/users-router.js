const bcrypt = require('bcryptjs'); // npm i bcryptjs
const router = require('express').Router();
const usersHelper = require('../users/users-model');
const validation = require("../auth/auth-router");
const secrets = require('../auth/secrets');
const jwt = require('jsonwebtoken'); // installed this library

router.post('/register', (req, res) => {
  let credentials = req.body;

  bcrypt.hash(credentials.password, 12, (err, hashedPassword) => {
    credentials.password = hashedPassword;

    usersHelper.add(credentials)
      .then(creds => {
        res.status(201).json(creds);
      })
      .catch(error => {
        res.status(500).json({ message: "Error while saving credentials to DB" });
      });
  });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;
  usersHelper.findBy(username)
    .then(user => {
      //console.log("correct hash? ", bcrypt.compareSync(password, user.password));
      console.log("user? ", user);
      if (user && bcrypt.compareSync(password, user.password)) {
        console.log("bcrypt");
        const token = generateToken(user);

        res.status(200).json({
          message: `Welcome ${user.username}!, have a token...`,
          token, // attach the token as part of the response
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json({ message: "Error finding user with that username" });
    });

});

function generateToken(user) {
  const payload = {
    subject: user.id, // sub in payload is what the token is about
    username: user.username,
    department: user.department
    // ...otherData
  };

  const options = {
    expiresIn: '1d', // show other available options in the library's documentation
  };

  // extract the secret away so it can be required and used where needed
  return jwt.sign(payload, secrets.jwtSecret, options); // this method is synchronous
}

router.get('/', validation, (req, res) => {

  usersHelper.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.status(500).json({ message: "Error getting users" }));

});

module.exports = router;