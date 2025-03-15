const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/user');
const mailchimp = require('../services/mailchimp');
const mailgun = require('../services/mailgun');
const keys = require('../config/keys');
const { EMAIL_PROVIDER } = require('../constants');

const { secret, tokenLife } = keys.jwt;

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'No user found for this email address.' });
    }

    if (user.provider !== EMAIL_PROVIDER.Email) {
      return res.status(400).json({ error: `Email is already used with ${user.provider} provider.` });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    const payload = { id: user.id };
    const token = jwt.sign(payload, secret, { expiresIn: tokenLife });

    res.status(200).json({
      success: true,
      token: `Bearer ${token}`,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ error: 'Login failed. Please try again.' });
  }
};

exports.register = async (req, res) => {
  try {
    const { email, firstName, lastName, password, isSubscribed } = req.body;

    if (!email || !firstName || !lastName || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already in use.' });
    }

    let subscribed = false;
    if (isSubscribed) {
      const result = await mailchimp.subscribeToNewsletter(email);
      if (result.status === 'subscribed') {
        subscribed = true;
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = new User({ email, password: hash, firstName, lastName });
    const registeredUser = await user.save();

    await mailgun.sendEmail(registeredUser.email, 'signup', null, registeredUser);

    const payload = { id: registeredUser.id };
    const token = jwt.sign(payload, secret, { expiresIn: tokenLife });

    res.status(200).json({
      success: true,
      subscribed,
      token: `Bearer ${token}`,
      user: {
        id: registeredUser.id,
        firstName: registeredUser.firstName,
        lastName: registeredUser.lastName,
        email: registeredUser.email,
        role: registeredUser.role
      }
    });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed. Please try again.' });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'No user found with this email.' });

    const resetToken = crypto.randomBytes(48).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    await mailgun.sendEmail(user.email, 'reset', req.headers.host, resetToken);

    res.status(200).json({ success: true, message: 'Check your email for reset instructions.' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to process request.' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password is required.' });

    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ error: 'Invalid or expired token.' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    await mailgun.sendEmail(user.email, 'reset-confirmation');

    res.status(200).json({ success: true, message: 'Password reset successfully.' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to reset password.' });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;
    const email = req.user.email;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Incorrect old password.' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(confirmPassword, salt);
    await user.save();

    await mailgun.sendEmail(user.email, 'reset-confirmation');

    res.status(200).json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to change password.' });
  }
};

exports.googleCallback = (req, res) => {
  const payload = { id: req.user.id };
  const token = jwt.sign(payload, secret, { expiresIn: tokenLife });
  res.redirect(`${keys.app.clientURL}/auth/success?token=Bearer ${token}`);
};

exports.facebookCallback = (req, res) => {
  const payload = { id: req.user.id };
  const token = jwt.sign(payload, secret, { expiresIn: tokenLife });
  res.redirect(`${keys.app.clientURL}/auth/success?token=Bearer ${token}`);
};
