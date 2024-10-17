import React from "react";
import "../App.css";
import { Link } from "react-router-dom";
import loginImage from "./../assets/images/6333040.jpg";

const Login = () => {
  return (
    <div className="container mx-auto flex justify-center items-center min-h-screen bg-gray-100 loginBack">
      <div className="flex flex-col sm:flex-row w-full max-w-4xl bg-white shadow-md rounded-lg overflow-hidden bg-opacity-80 backdrop-blur-sm">
        {/* Left side with image */}
        <div className="w-full sm:w-1/2">
          <img
            src={loginImage} // Replace with your image URL
            alt="Login Illustration"
            className="object-cover w-full h-full"
          />
        </div>

        {/* Right side with form */}
        <div className="w-full sm:w-1/2 p-8">
          <h2 className="text-2xl font-bold text-center mb-6">
            Please Login Here
          </h2>

          {/* Username Input */}
          <div className="mb-4">
            <label
              className="block text-gray-700 font-semibold mb-2"
              htmlFor="username"
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              placeholder="Enter your username"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Password Input */}
          <div className="mb-6">
            <label
              className="block text-gray-700 font-semibold mb-2"
              htmlFor="password"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              placeholder="Enter your password"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Submit Button */}
          <div className="flex justify-center">
            <button className="w-full bg-blue-500 text-white font-semibold py-2 px-6 rounded-md hover:bg-blue-600 transition">
              Login
            </button>
          </div>

          {/* Register Link */}
          <div className="text-center mt-8">
            <p className="text-gray-600">
              Don't have an account?{" "}
              <Link to="/register" className="text-blue-500 hover:underline">
                Register here
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
