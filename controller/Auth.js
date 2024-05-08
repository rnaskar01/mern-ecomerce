const { User } = require("../model/User");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { sanitizeUser, sendMail } = require("../services/common");


exports.createUser = async (req, res) => {
  // this product we have to get from API body
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
        const user = new User({ ...req.body, password: hashedPassword, salt });
        const doc = await user.save();

        req.login(sanitizeUser(doc), (err) => {
          // this is calls serializer and adds this session
          if (err) {
            res.status(400).json(err);
          } else {
            const token = jwt.sign(sanitizeUser(doc), process.env.JWT_SECRET_KEY);
            res
              .cookie("jwt", token, {
                expires: new Date(Date.now() + 3600000),
                httpOnly: true,
              })
              .status(201)
              .json({id:doc.id, role:doc.role});
          }
        });
      }
    );
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.loginUser = async (req, res) => {
  const user = req.user;
  res
  .cookie("jwt", user.token, {
    expires: new Date(Date.now() + 3600000),
    httpOnly: true,
  })
  .status(201)
  .json({id:user.id, role:user.role});
};


exports.logout = async (req, res) => {
  res
  .cookie("jwt", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  })
  .sendStatus(200)
};


exports.checkAuth = async (req, res) => {
  if(req.user){
    res.json(req.user );
  }else{
    res.sendStatus(401)
  }
};

exports.resetPasswordRequest = async (req, res) => {
  const email = req.body.email;
  const user = await User.findOne({email:email})

  if(user){
    const token = crypto.randomBytes(64).toString('hex');
    user.resetPasswordToken = token;
    await user.save();

    // Also set token in email
    const resetPageLink = "http://localhost:3000/reset-password?token="+token+'&email='+email;
    const subject = "reset password for e-comerce Application"
    const html = `<p>Click <a href='${resetPageLink}'>here</a> to Reset Password</p>`
  
  // let send email and a token in the email body so we can verify that user has clicked right link
  
    if(email){
      const response = await sendMail({to:email,subject,html})
      res.json(response);
    }else{
      res.sendStatus(401)
    }
  }else{
    res.json(400);
  }

 
};



exports.resetPassword = async (req, res) => {
const {email,password,token} = req.body;


  const user = await User.findOne({email:email, resetPasswordToken:token})

  if(user){

    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
        user.password = hashedPassword;
        user.salt=salt;
        await user.save();
        const subject = "Password successfully reset for e-comerce"
        const html = `<p>Successfully able to Reset Password</p>`  
        if(email){
          const response = await sendMail({to:email,subject,html})
          res.json(response);
        }else{
          res.sendStatus(401)
        }
      })
  }else{
    res.json(400);
  }

 
};