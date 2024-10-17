import React, { useState } from "react";

const Feedback = () => {
  const [name, setName] = useState("");
  const [rating, setRating] = useState("");
  const [message, setMessage] = useState("");
  const [feedbackList, setFeedbackList] = useState([]);

  const handleSubmit = (e) => {
    e.preventDefault();

    // Create a new feedback object
    const newFeedback = { name, rating, message, id: feedbackList.length + 1 };

    // Add the new feedback to the feedback list
    setFeedbackList([newFeedback, ...feedbackList]);

    // Clear form fields after submission
    setName("");
    setRating("");
    setMessage("");
  };

  return (
    <div className="max-w-xl mx-auto p-6 bg-white shadow-md rounded-lg">
      <h2 className="text-2xl font-bold mb-4 text-center text-gray-800">
        Doctor Feedback
      </h2>

      {/* Feedback Form */}
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label
            htmlFor="name"
            className="block text-gray-700 font-semibold mb-2"
          >
            Patient Name:
          </label>
          <input
            type="text"
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full px-4 py-2 border rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter your name"
          />
        </div>
        <div className="mb-4">
          <label
            htmlFor="rating"
            className="block text-gray-700 font-semibold mb-2"
          >
            Rating:
          </label>
          <select
            id="rating"
            value={rating}
            onChange={(e) => setRating(e.target.value)}
            required
            className="w-full px-4 py-2 border rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Select Rating</option>
            <option value="5">5 - Excellent</option>
            <option value="4">4 - Very Good</option>
            <option value="3">3 - Good</option>
            <option value="2">2 - Fair</option>
            <option value="1">1 - Poor</option>
          </select>
        </div>
        <div className="mb-4">
          <label
            htmlFor="message"
            className="block text-gray-700 font-semibold mb-2"
          >
            Feedback Message:
          </label>
          <textarea
            id="message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            required
            className="w-full px-4 py-2 border rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Write your feedback"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white font-semibold py-2 px-4 rounded-lg hover:bg-blue-600 transition duration-300"
        >
          Submit Feedback
        </button>
      </form>

      {/* Display Feedback List */}
      <div className="mt-8">
        <h3 className="text-xl font-bold mb-4">Previous Feedback</h3>
        {feedbackList.length > 0 ? (
          feedbackList.map((feedback) => (
            <div
              key={feedback.id}
              className="mb-4 p-4 border rounded-lg shadow-sm bg-gray-50"
            >
              <p className="font-semibold">Patient: {feedback.name}</p>
              <p>Rating: {feedback.rating} / 5</p>
              <p className="mt-2">{feedback.message}</p>
            </div>
          ))
        ) : (
          <p>No feedback submitted yet.</p>
        )}
      </div>
    </div>
  );
};

export default Feedback;
