const User = require("../users/users-model")

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted() {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user) {
        return res.status(401).json({
          message: "You shall not pass!"
        })
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
function checkUsernameFree() {
  return async (req, res, next) => {
    try {
      const { username } = req.params
      const user = await User.getBy(username)

      if (user) {
        return res.status(422).json({
          message: "Username taken"
        })
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists() {
  return async (req, res, next) => {
    try {
      const { username } = req.params
      const user = await User.getBy(username)

      if (user) {
        return res.status(401).json({
          message: "Invalid credentials"
        }) 
      } else {
        req.user = user
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength() {
  return async (req, res, next) => {
    try {
      const { password } = req.params

      if (!password || password.length < 3) {
        return res.status(422).json({
          message: "Password length must be longer than 3 chars"
        })
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
}