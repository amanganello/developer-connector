const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

//  @route      POST     api/users/register
//  @desc       Register user
//  @access     Public
router.post('/register', [
    check('name', 'Name is required')
        .not()
        .isEmpty(),
    check('email', 'Please include a valid email')
        .isEmail(),
    check('password',
        'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 })
],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        };
        const { name, email, password } = req.body;

        try {
            // Check if user exists
            let user = await User.findOne({ email });

            if (user) {
                return res.status(400).json({
                    errors: [{
                        msg: 'User already exists'
                    }]
                });
            }

            // Get users gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // Encrypt password
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 3600000 },
                (error, token) => {
                    if (error) throw error;
                    res.json({ token });
                });
        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server error');
        }
    }
);

//@route Get api/users/login
//@desc Login User / Returning JWT  Token
//@access Public
router.post('/login', (req, res) => {

    const { errors, isValid } = validateLoginInput(req.body);

    //checking validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    //Find user by email
    User.findOne({ email }).then(user => {
        //check for user
        if (!user) {
            errors.email = 'User not found';
            return res.status(404).json(errors);
        }

        //check password
        bcrypt.compare(password, user.password).then(isMatch => {
            if (isMatch) {
                //User matched
                //Create JWT Payload
                const payload = {
                    id: user.id,
                    name: user.name,
                    avatar: user.avatar
                };

                //Sign the Token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    { expiresIn: 7200 },
                    (err, token) => {
                        res.json({
                            success: true,
                            token: 'Bearer ' + token
                        });
                    }
                );
            } else {
                errors.password = 'Password incorrect';
                return res.status(400).json(errors);
            }
        });
    });
});

module.exports = router;
