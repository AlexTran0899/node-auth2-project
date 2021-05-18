const { JWT_SECRET } = require("../secrets"); // use this secret!
const yup = require('yup')
const jwt = require('jsonwebtoken')
const messageSchema = yup.object({
  username: yup.string(),
  password: yup.string().required("/ must be longer than 3/i").min(3, "/ must be longer than 3/i"),
  role_name: yup.string().trim().max(32,'can not be longer than 32 chars')
})

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: 'token invalid' })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  } else {
    next({ status: 401, message: 'token required' })
  }
}

const only = role_name => (req, res, next) => {
  console.log(req.decodedJwt.role_name )
  if (req.decodedJwt.role_name === role_name) next()
  else next({ status: 403, message: 'this is not for you'})
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    next()
}


const validateRoleName = async (req, res, next) => {
  try {
    const validate = await messageSchema.validate(req.body, { stripUnknown: true })
    if(validate.role_name === 'admin'){
      next({status: 422, message: 'can not be admin'})
    } else {
      req.body = validate
      next()
    }
  } catch (err) {
    next({ status: 422, message: err.message })
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
