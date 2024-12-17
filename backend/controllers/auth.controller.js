import User from "../models/user.model.js";
import { redis } from "../lib/redis.js";
import jwt from "jsonwebtoken";

const generateToken = (userId) => {
  const accesstoken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshtoken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
  return { accesstoken, refreshtoken };
};

const storeRefreshToken = async (userId, refreshToken) => {
  try {
    await redis.set(
      `refresh_token:${userId}`,
      refreshToken,
      "EX",
      7 * 24 * 60 * 60
    ); // 7 days
  } catch (err) {
    console.log(err);
  }
};

const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // prevent XSS attacks, cross site scripting attack
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", // prevent CSRF attacks, cross-site request forgeny attack
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // prevent XSS attacks, cross site scripting attack
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", // prevent CSRF attacks, cross-site request forgeny attack
    maxAge: 7 * 24 * 60 * 60 * 1000, // 15 minutes
  });
};

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log("name, email, password", name, email, password);
    const existUser = await User.findOne({ email });

    if (existUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = new User({ name, email, password });

    // Authentication
    const { accesstoken, refreshtoken } = generateToken(user._id);

    await storeRefreshToken(user._id, refreshtoken);

    setCookies(res, accesstoken, refreshtoken);

    await user.save();

    return res.status(201).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User created successfully",
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    return res.status(200).json({ user, message: "Login successful" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: err.message });
  }
};
export const logout = async (req, res) => {
  res.send("Logout is called");
};
