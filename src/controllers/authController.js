const crypto = require('crypto');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');

// @desc      Register user
// @route     POST /api/auth/register
// @access    Public
exports.register = async (req, res, next) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        // Create user
        const user = await User.create({
            firstName,
            lastName,
            email,
            password,
            isActive: process.env.NODE_ENV === 'development',
        });

        // Create verification token
        const verificationToken = user.getVerificationToken();

        await user.save({ validateBeforeSave: false });

        // Create activation url
        // Frontend URL:
        const activationUrl = `${req.protocol}://${req.get(
            'host'
        )}/api/auth/activate/${verificationToken}`; // This should point to frontend ideally, but if API handles it, it can redirect.
        // Requirement: "User clicks activation link -> Account becomes active".
        // Usually link points to Frontend Page -> Frontend calls API.
        // Or Link points to API -> API activates and redirects to Frontend Login.
        // Let's point to Frontend Page to keep it clean.
        // Frontend URL should be from env or derived?
        // Let's assume frontend is localhost:5173 or whatever.
        // Better to use env CLIENT_URL.

        const clientUrl = process.env.CLIENT_URL || 'https://cloudra-frontend.vercel.app';
        const message = `You are receiving this email because you (or someone else) has requested the creation of an account. Please click on the link below to activate your account:\n\n${clientUrl}/activate/${verificationToken}`;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Account Activation',
                message,
            });

            res.status(200).json({ success: true, data: 'Email sent' });
        } catch (err) {
            console.error('Registration Email Error:', err);
            user.verificationToken = undefined;
            user.verificationTokenExpire = undefined;
            await user.save({ validateBeforeSave: false });
            return res.status(500).json({
                success: false,
                error: `Account created but activation email failed to send: ${err.message}`
            });
        }
    } catch (err) {
        console.error('Registration DB Error:', err);
        if (err.code === 11000) {
            return res.status(400).json({ success: false, error: 'Email already exists' });
        }
        next(err);
    }
};

// @desc      Activate user
// @route     PUT /api/auth/activate/:token
// @access    Public
exports.activateAccount = async (req, res, next) => {
    try {
        const verificationToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            verificationToken,
            verificationTokenExpire: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ success: false, error: 'Invalid token' });
        }

        user.isActive = true;
        user.verificationToken = undefined;
        user.verificationTokenExpire = undefined;

        await user.save();

        sendTokenResponse(user, 200, res);
    } catch (err) {
        next(err);
    }
};

// @desc      Login user
// @route     POST /api/auth/login
// @access    Public
exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validate email & password
        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Please provide an email and password' });
        }

        // Check for user
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        // Check if matching password
        const isMatch = await user.matchPassword(password);

        if (!isMatch) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        // Check if active
        if (!user.isActive) {
            return res.status(401).json({ success: false, error: 'Please activate your account first' });
        }

        sendTokenResponse(user, 200, res);
    } catch (err) {
        next(err);
    }
};

// @desc      Get current logged in user
// @route     GET /api/auth/me
// @access    Private
exports.getMe = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);

        res.status(200).json({
            success: true,
            data: user,
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Forgot password
// @route     POST /api/auth/forgotpassword
// @access    Public
exports.forgotPassword = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (!user) {
            return res.status(404).json({ success: false, error: 'There is no user with that email' });
        }

        // Get reset token
        const resetToken = user.getResetPasswordToken();

        await user.save({ validateBeforeSave: false });

        // Create reset url
        const clientUrl = process.env.CLIENT_URL || 'https://cloudra-frontend.vercel.app';
        const resetUrl = `${clientUrl}/reset-password/${resetToken}`;

        const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Password Reset Token',
                message,
            });

            res.status(200).json({ success: true, data: 'Email sent' });
        } catch (err) {
            console.log(err);
            user.resetPasswordToken = undefined;
            user.resetPasswordTokenExpire = undefined;

            await user.save({ validateBeforeSave: false });

            return res.status(500).json({ success: false, error: 'Email could not be sent' });
        }
    } catch (err) {
        next(err);
    }
};

// @desc      Reset password
// @route     PUT /api/auth/resetpassword/:token
// @access    Public
exports.resetPassword = async (req, res, next) => {
    try {
        // Get hashed token
        const resetPasswordToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordTokenExpire: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ success: false, error: 'Invalid token' });
        }

        // Set new password
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordTokenExpire = undefined;

        await user.save();

        sendTokenResponse(user, 200, res);
    } catch (err) {
        next(err);
    }
};

// Get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
    // Create token
    const token = user.getSignedJwtToken();

    const options = {
        expires: new Date(
            Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };

    if (process.env.NODE_ENV === 'production') {
        options.secure = true;
    }

    res
        .status(statusCode)
        .cookie('token', token, options)
        .json({
            success: true,
            token,
            user
        });
};
