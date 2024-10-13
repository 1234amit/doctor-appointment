import React from "react";

const DoctorCard = ({ doctor }) => {
  const {
    name,
    specialty,
    avgRating,
    totalRating,
    photo,
    totalPatients,
    hospital,
  } = doctor;
  return (
    <>
      <div
        className="mx-auto bg-white rounded-lg shadow-lg overflow-hidden p-5 my-10"
        style={{ width: "350px", height: "380px" }}
      >
        <div className="flex items-center space-x-4">
          <img
            className="w-16 h-16 rounded-full object-cover"
            src={photo}
            alt={name}
          />
          <div>
            <h3 className="text-xl font-semibold text-gray-800">{name}</h3>
            <p className="text-gray-500">{specialty}</p>
          </div>
        </div>

        <div className="mt-4">
          <p className="text-gray-700 font-bold">Hospital:</p>
          <p className="text-gray-500">{hospital}</p>
        </div>

        <div className="mt-4">
          <p className="text-gray-700 font-bold">Total Patients:</p>
          <p className="text-gray-500">{totalPatients}</p>
        </div>

        <div className="mt-4 flex items-center">
          <p className="text-gray-700 font-bold">Rating:</p>
          <div className="ml-2 flex items-center">
            <span className="text-yellow-500 text-lg">★</span>
            <span className="text-gray-700 ml-1">{avgRating}</span>
            <span className="text-gray-500 ml-1">({totalRating} reviews)</span>
          </div>
        </div>

        <button className="mt-6 w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 transition duration-300">
          View Profile
        </button>
      </div>
    </>
  );
};

export default DoctorCard;
