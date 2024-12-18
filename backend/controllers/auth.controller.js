import User from "../models/user.model.js";
import redis from "../lib/redis.js";
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
  if (!res || !accessToken || !refreshToken) {
    throw new Error("setCookies: missing required parameter");
  }

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
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existUser = await User.findOne({ email });

    if (existUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = new User({ name, email, password });

    // Authentication
    const { accesstoken, refreshtoken } = generateToken(user._id);
    await storeRefreshToken(user._id, refreshtoken);

    // Store token to cookies
    setCookies(res, accesstoken, refreshtoken);

    // Save user to DB
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
    console.log("Error in signup controller", err.message);
    res.status(500).json({ message: err.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      const { accesstoken, refreshtoken } = generateToken(user._id);
      await storeRefreshToken(user._id, refreshtoken);
      setCookies(res, accesstoken, refreshtoken);
      return res.status(200).json({
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        message: "Login successful",
      });
    } else {
      return res.status(401).json({ message: "Invalid email or password!" });
    }
  } catch (err) {
    console.log("Error in login controller", err.message);
    res.status(500).json({ message: err.message });
  }
};

export const logout = async (req, res) => {
  try {
    const refresh_token = req.cookies.refreshToken;
    if (refresh_token) {
      const decoded = jwt.verify(
        refresh_token,
        process.env.REFRESH_TOKEN_SECRET
      );
      await redis.del(`refresh_token:${decoded.userId}`);
    }

    await res.clearCookie("accessToken");
    await res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logout successful" });
  } catch (err) {
    console.log("Error in logout controller", err.message);
    res.status(500).json({ message: err.message });
  }
};

export const renewToken = async (req, res) => {
  try {
    const refresh_token = req.cookies.refreshToken;

    if (!refresh_token) {
      return res.status(401).json({ message: "No refresh token provided!" });
    }

    const decoded = jwt.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET);

    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

    if (storedToken !== refresh_token) {
      return res.status(404).json({ message: "Invalid refresh Token!" });
    }

    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "15m",
      }
    );

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      maxAge: 15 * 60 * 1000,
    });

    res.status(200).json({ message: "Token renewed successfully" });
  } catch (err) {
    console.log("Error in renewToken controller", err.message);
    res.status(500).json({ message: err.message });
  }
};

export const getProfile = async (req, res) => {
  try {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) {
      return res.status(401).json({ message: "No access token provided!" });
    }

    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decoded.userId);

    return res.status(200).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.log("Error in getProfile controller", err.message);
    res.status(500).json({ message: err.message });
  }
};
