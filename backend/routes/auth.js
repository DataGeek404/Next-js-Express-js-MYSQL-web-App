const express = require('express');
const router = express.Router();
const passport = require('passport');

router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication
    const token = generateJWT(req.user); // Implement your JWT generation
    res.redirect(`http://localhost:3000/auth-redirect?token=${token}`);
  }
);

//Export the router app

module.exports = router;
