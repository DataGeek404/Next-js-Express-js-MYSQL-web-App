// Example using Express.js and Passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // 1. Check if user exists in your DB
      let user = await User.findOne({ googleId: profile.id });
      
      // 2. If not, create a new user
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          // Add other fields as needed
        });
      }
      
      // 3. Return user object
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Routes
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication
    const token = generateJWT(req.user);
    res.redirect(`http://localhost:3000/auth-redirect?token=${token}`);
  }
);