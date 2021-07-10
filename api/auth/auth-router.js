const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, async(req, res, next) => {
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
    const credentials = req.body;

    try {
      const hash = bcryptjs.hashSync(credentials.password, 10);
      credentials.password = hash;
  
      const user = await Users.add(credentials);
      const token = generateToken(user);
      res.status(201).json({ data: user, token });
    } catch (err) {
      console.log(err);
      next({ apiCode: 500, apiMessage: 'error saving new user', ...err });
    }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
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
    const { username, password } = req.body;

    try {
  
      const [user] =  Users.findBy({ username: username });
      if (user && bcryptjs.compareSync(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({ message: 'welcome to the api', token: token });
      } else {
        next({ apiCode: 401, apiMessage: 'invalid credentials' });
      }
    } catch (err) {
      next({ apiCode: 500, apiMessage: 'db error logging in', ...err });
    }
});
function generateToken(user) {

  const payload = {
    subject: user.id,
    username: user.username,
    rolename: user.rolename
  };
  const options = {
    expiresIn: "1d"
  };

  const token = jwt.sign(payload, JWT_SECRET, options);

  return token;
}

module.exports = router;
