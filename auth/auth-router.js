const jwt = require('jsonwebtoken')
const secrets = require('../auth/secrets');

module.exports = (req, res, next) => {
  console.log(req.headers);
  let token = req.headers.authorization;

  if (token) {

    let secret = secrets.jwtSecret;

    console.log("sercret", secret);

    jwt.verify(token, secret, (error, decodedToken) => {

      if (error) {
        res.status(401).json({ message: `Error decoding token` })
      }
      else {
        res.decodedToken = decodedToken;
        next();
      }

    })
  }
  else {
    res.status(400).json({ message: 'No credentials provided' });
  }
}