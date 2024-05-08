require('dotenv').config();
const express = require('express');
const server = express();
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const jwt = require('jsonwebtoken');
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const mongoose = require("mongoose");
const productsRouters = require("./routes/Products");
const categoriesRouters = require("./routes/Category");
const brandsRouters = require("./routes/Brands");
const userRouters = require("./routes/User");
const authRouters = require("./routes/Auth");
const cartRouters = require("./routes/Cart");
const ordersRouters = require("./routes/Order");
const { User } = require("./model/User");
const crypto = require("crypto");
const { isAuth, sanitizeUser, cookieExtractor } = require("./services/common");
const cookieParser = require("cookie-parser");
const path = require('path')


// jwt options

const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECRET_KEY; //: should not be in the code
//middlewares...

server.use(express.static(path.resolve(__dirname,'build')))
server.use(cookieParser())
server.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  })
);
server.use(passport.authenticate("session"));

server.use(
  cors({
    exposedHeaders: ["X-Total-Count"],
  })
);
server.use(express.json()); // to parse req.body
server.use("/products", isAuth(), productsRouters.router); // we can also use jwt token for client-only auth
server.use("/categories",isAuth(), categoriesRouters.router);
server.use("/brands",isAuth(), brandsRouters.router);
server.use("/users",isAuth(), userRouters.router);
server.use("/auth", authRouters.router);
server.use("/cart", isAuth(),cartRouters.router);
server.use("/orders",isAuth(), ordersRouters.router);

server.get('*',(req,res)=> res.sendFile(path.resolve('build','index.html')));
// Email endpoint

// passport Strategies

passport.use(
  "local",
  new LocalStrategy(
    {usernameField:'email'},
    async function (email, password, done) {
    // by default passport uses username
    try {
      const user = await User.findOne({ email: email }).exec();
      if (!user) {
        return done(null, false, { message: "No such a user found" });
      }
      crypto.pbkdf2(
        password,
        user.salt,
        310000,
        32,
        "sha256",
        async function (err, hashedPassword) {
          if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
            return done(null, false, {
              message: "Invalid email id or password",
            });
          }
          const token = jwt.sign(sanitizeUser(user), process.env.JWT_SECRET_KEY);
          //console.log(token);
          done(null, {id:user.id, role:user.role,token});
        }
      );
    } catch (err) {
      done(err);
    }
  })
);

passport.use(
  "jwt",
  new JwtStrategy(opts, async function (jwt_payload, done) {
   // console.log({jwt_payload});
    try {
      const user = await User.findById(jwt_payload.id)
      if (user) {
        return done(null, sanitizeUser(user)); // this is called serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);

    }   
  })
);

// this create session variable req.user on being called from callbacks
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, role: user.role });
  });
});

// this changes session variable req.user when called from authorized request
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});


main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(process.env.MONGODB_URL);
  console.log("database connected...");
}

server.listen(process.env.PORT, () => {
  console.log("server started...");
});
