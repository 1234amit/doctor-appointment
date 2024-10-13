import React from "react";

const Footer = () => {
  return (
    <footer className="bg-gray-800 text-white py-8">
      <div className="container mx-auto px-4 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Logo and About Section */}
          <div>
            <h2 className="text-2xl font-bold mb-4">Your Logo</h2>
            <p className="text-gray-400">
              Providing exceptional care and services since 1990. We are
              committed to your health and well-being.
            </p>
          </div>

          {/* Quick Links Section */}
          <div>
            <h3 className="text-xl font-semibold mb-4">Quick Links</h3>
            <ul>
              <li className="mb-2">
                <a
                  href="#"
                  className="text-gray-400 hover:text-white transition"
                >
                  Home
                </a>
              </li>
              <li className="mb-2">
                <a
                  href="#"
                  className="text-gray-400 hover:text-white transition"
                >
                  About Us
                </a>
              </li>
              <li className="mb-2">
                <a
                  href="#"
                  className="text-gray-400 hover:text-white transition"
                >
                  Services
                </a>
              </li>
              <li className="mb-2">
                <a
                  href="#"
                  className="text-gray-400 hover:text-white transition"
                >
                  Contact
                </a>
              </li>
            </ul>
          </div>

          {/* Contact Information Section */}
          <div>
            <h3 className="text-xl font-semibold mb-4">Contact Us</h3>
            <p className="text-gray-400">
              1234 Health St, Wellness City, HC 56789
            </p>
            <p className="text-gray-400">Email: info@yourcompany.com</p>
            <p className="text-gray-400">Phone: (123) 456-7890</p>

            <div className="mt-4">
              {/* Social Media Icons */}
              <a href="#" className="text-gray-400 hover:text-white mx-2">
                <i className="fab fa-facebook"></i>
              </a>
              <a href="#" className="text-gray-400 hover:text-white mx-2">
                <i className="fab fa-twitter"></i>
              </a>
              <a href="#" className="text-gray-400 hover:text-white mx-2">
                <i className="fab fa-instagram"></i>
              </a>
              <a href="#" className="text-gray-400 hover:text-white mx-2">
                <i className="fab fa-linkedin"></i>
              </a>
            </div>
          </div>
        </div>

        <div className="mt-8 text-center text-gray-500">
          &copy; 2024 Your Company. All rights reserved.
        </div>
      </div>
    </footer>
  );
};

export default Footer;
