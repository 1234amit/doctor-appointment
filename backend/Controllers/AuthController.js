import User from "../models/UserSchema.js";
import Doctor from "../models/DoctorSchema.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET_KEY,
    {
      expiresIn: "15d",
    }
  );
};

export const register = async (req, res) => {
  const { name, email, password, role, gender, photo } = req.body;
  try {
    let user = null;
    if (role === "patient") {
      user = await User.findOne({ email });
    } else if (role === "doctor") {
      user = await Doctor.findOne({ email });
    }
    //check user is exist
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }
    //hash password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    if (role === "patient") {
      user = new User({
        name,
        email,
        password: hashPassword,
        role,
        gender,
        photo,
      });
    }

    if (role === "doctor") {
      user = new Doctor({
        name,
        email,
        password: hashPassword,
        role,
        gender,
        photo,
      });
    }

    await user.save();
    res
      .status(200)
      .json({ success: true, message: "User Register Successfully" });
  } catch (err) {
    res.status(200).json({
      success: false,
      message: "Internal Server Error. Please Try again later",
    });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    let user = null;
    const patient = await User.findOne({ email });
    const doctor = await Doctor.findOne({ email });

    if (patient) {
      user = patient;
    }

    if (doctor) {
      user = doctor;
    }

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ message: "User does not exist" });
    }

    // Compare password
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    // Return error if password does not match
    if (!isPasswordMatch) {
      return res
        .status(401)
        .json({ status: false, message: "Invalid Credentials" });
    }

    // Generate token
    const token = generateToken(user);

    // Destructure to exclude sensitive data
    const { password: _, role, appointments, ...rest } = user._doc;

    res.status(200).json({
      status: true,
      message: "Successfully Logged In",
      token,
      data: { ...rest },
      role,
    });
  } catch (err) {
    console.error("Login error:", err); // Log the actual error
    res.status(500).json({ status: false, message: "Failed to login" });
  }
};
