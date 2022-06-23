const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

/**
  [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

  response:
  status 201
  {
    "user"_id: 3,
    "username": "anna",
    "role_name": "angel"
  }
*/

router.post("/register", validateRoleName, (request, response, next) => {
  const { username, password } = request.body;
  const { role_name } = request;
  const hash = bcrypt.hashSync(password, 12);
  Users.add({ username, password: hash, role_name })
    .then(newUser => {
      response.status(201).json(newUser);
    })
    .catch(next);
});

/**
  [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "sue is back!",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
  }

  The token must expire in one day, and must provide the following information
  in its payload:

  {
    "subject"  : 1       // the user_id of the authenticated user
    "username" : "bob"   // the username of the authenticated user
    "role_name": "admin" // the role of the authenticated user
  }
*/

router.post("/login", checkUsernameExists, (request, response, next) => {

});

module.exports = router;
