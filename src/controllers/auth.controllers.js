import { asyncHandler } from "../utils/async-handler.js";
import User from "../models/user.models.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Helper function to set up nodemailer transporter
const createEmailTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: process.env.MAILTRAP_PORT,
    secure: false,
    auth: {
      user: process.env.MAILTRAP_USERNAME,
      pass: process.env.MAILTRAP_PASSWORD,
    },
  });
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, fullName } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({
      message: "All fields are required",
    });
  }

  const existingUser = await User.findOne({ 
    $or: [{ email }, { username }] 
  });
  
  if (existingUser) {
    return res.status(400).json({
      message: existingUser.email === email 
        ? "Email already registered" 
        : "Username already taken",
    });
  }

  // Create user
  const user = await User.create({
    username,
    email,
    password,
    fullName,
  });

  if (!user) {
    return res.status(400).json({
      message: "User not registered",
    });
  }

  // Generate secure email verification token
  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  await user.save();

  // Setup email
  const transporter = createEmailTransporter();
  const mailOptions = {
    from: process.env.MAILTRAP_SENDEREMAIL,
    to: user.email,
    subject: "Verify your email",
    text: `Please click on the following link to verify your email:
${process.env.BASE_URL}/api/v1/users/verify/${unHashedToken}
Note: This link will expire in 20 minutes.`,
  };

  await transporter.sendMail(mailOptions);

  res.status(201).json({
    message: "User registered successfully. Verification email sent.",
    success: true,
  });
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Step 1: Check for missing credentials
  if (!email || !password) {
    return res.status(400).json({
      message: "Empty Credentials",
    });
  }

  // Step 2: Find user in DB
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({
      message: "User not found in the DB",
    });
  }

  // Step 3: Check if password matches
  const isMatch = await user.isPasswordCorrect(password);
  if (!isMatch) {
    return res.status(400).json({
      message: "Invalid Credentials",
    });
  }

  // Step 4: Generate tokens
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  // Step 5: Save refresh token in DB
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  // Step 6: Send response
  res.status(200).json({
    message: "Login successful",
    accessToken,
    refreshToken,
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      fullName: user.fullName,
    },
  });
});

const logoutUser = asyncHandler(async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({
      message: "Email is required to logout",
    });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({
      message: "User not found",
    });
  }

  // Clear refresh token
  user.refreshToken = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    message: "User logged out successfully",
  });
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({
      message: "Verification token is required",
    });
  }

  // Hash the received token to compare with stored token
  const hashedToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  // Find user with this token and valid expiry
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({
      message: "Invalid or expired token",
    });
  }

  // Verify the user
  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    message: "Email verified successfully",
    success: true,
  });
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  if (user.isEmailVerified) {
    return res.status(400).json({ message: "Email is already verified" });
  }

  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // Setup nodemailer
  const transporter = createEmailTransporter();
  const mailOptions = {
    from: process.env.MAILTRAP_SENDEREMAIL,
    to: user.email,
    subject: "Resend Email Verification",
    text: `Please verify your email by clicking this link:
${process.env.BASE_URL}/api/v1/users/verify/${unHashedToken}
This link will expire in 20 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({
      message: "Verification email resent successfully",
      success: true,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error sending verification email",
      error: error.message,
    });
  }
});

const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ 
      message: "Token and new password are required" 
    });
  }

  // Hash the token to compare with stored token
  const hashedToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  // Find user with this token and valid expiry
  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({
      message: "Invalid or expired token",
    });
  }

  // Update password
  user.password = newPassword;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();

  res.status(200).json({
    message: "Password reset successfully",
    success: true,
  });
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token required" });
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // Find user with this refresh token
    const user = await User.findById(decoded._id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Generate new access token
    const newAccessToken = user.generateAccessToken();

    res.status(200).json({
      accessToken: newAccessToken,
      message: "Access token refreshed successfully",
    });
  } catch (error) {
    return res.status(401).json({ 
      message: "Invalid or expired refresh token",
      error: error.message
    });
  }
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Generate token
  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  // Send email
  const transporter = createEmailTransporter();
  const mailOptions = {
    from: process.env.MAILTRAP_SENDEREMAIL,
    to: user.email,
    subject: "Reset your password",
    text: `Click the link to reset your password:
${process.env.BASE_URL}/reset-password/${unHashedToken}
This link will expire in 20 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({
      message: "Password reset email sent successfully",
      success: true,
    });
  } catch (error) {
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return res.status(500).json({
      message: "Error sending password reset email",
      error: error.message,
    });
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user._id; // Assuming auth middleware adds user to req

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      message: "Both current password and new password are required",
    });
  }

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  // Check if current password is correct
  const isPasswordCorrect = await user.isPasswordCorrect(currentPassword);
  if (!isPasswordCorrect) {
    return res.status(400).json({
      message: "Current password is incorrect",
    });
  }

  // Update password
  user.password = newPassword;
  await user.save();

  res.status(200).json({
    message: "Password changed successfully",
    success: true,
  });
});

const getCurrentUser = asyncHandler(async (req, res) => {
  const userId = req.user._id; // Assuming auth middleware adds user to req

  const user = await User.findById(userId).select("-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry");
  
  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  res.status(200).json({
    user,
    success: true,
  });
});

const updateUserProfile = asyncHandler(async (req, res) => {
  const userId = req.user._id; // Assuming auth middleware adds user to req
  const { fullName, username } = req.body;
  
  // Find user
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  // Check if username already exists if updating username
  if (username && username !== user.username) {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        message: "Username already taken",
      });
    }
    user.username = username;
  }

  // Update full name if provided
  if (fullName) {
    user.fullName = fullName;
  }

  await user.save();

  res.status(200).json({
    message: "Profile updated successfully",
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      fullName: user.fullName,
      avatar: user.avatar,
    },
    success: true,
  });
});

const updateAvatar = asyncHandler(async (req, res) => {
  const userId = req.user._id; // Assuming auth middleware adds user to req
  const avatarLocalPath = req.file?.path; // Assuming multer middleware
  
  if (!avatarLocalPath) {
    return res.status(400).json({
      message: "Avatar file is required",
    });
  }

  // Find user
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  // Upload to cloudinary (assuming you have this utility)
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  if (!avatar.url) {
    return res.status(500).json({
      message: "Error while uploading avatar",
    });
  }

  // Delete old avatar from cloudinary if it exists
  if (user.avatar && user.avatar.url && !user.avatar.url.includes("placeholder")) {
    await deleteFromCloudinary(user.avatar.url);
  }

  // Update user avatar
  user.avatar = {
    url: avatar.url,
    localPath: avatarLocalPath,
  };

  await user.save();

  res.status(200).json({
    message: "Avatar updated successfully",
    avatar: user.avatar,
    success: true,
  });
});

export {
  registerUser,
  loginUser,
  logoutUser,
  verifyEmail,
  resendEmailVerification,
  resetForgottenPassword,
  refreshAccessToken,
  forgotPasswordRequest,
  changeCurrentPassword,
  getCurrentUser,
  updateUserProfile,
  updateAvatar
};