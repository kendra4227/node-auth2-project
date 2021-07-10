const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
          if (err) {
            next({ apiCode: 401, apiMessage: 'Token required' });
          } else {
            req.decodedToken = decodedToken;
            next();
          }
        });
      } else {
        next({ apiCode: 401, apiMessage: 'Token required' });
      }
    } catch (err) {
      next({ apiCode: 500, apiMessage: 'Token ivalid', ...err });
    }
}


const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    if ((req?.decodedJwt?.role || '') === role) {
      next();
    } else {
        res.status(403).json({ message: 'This is not for you' });
      }
  
}


const checkUsernameExists = async(req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const users = await Users.find();
    const searchedUser = req.body;
  
    for(let i = 0; i < users.length; i++) {
      if(searchedUser.username === users[i].username) {
        next();
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      };
    };
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
    const role = req.role_name;

    if(role === '' || !role) {
     role = 'student'
    } else {
      if(role = "admin") {
        res.status(422).json({message: "Role name can not be admin"})
      } else if (role.length < 32) {
        res.status(422).json({message: "Role name can not be longer than 32 chars"})
      }
    }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
