import React from "react";

const SidePanel = () => {
  return (
    <>
      <div className="shadow-lg p-3 lg:p-5 rounded-md">
        <div className="flex items-center justify-between">
          <p className="text__para mt-0 font-semibold">Ticket Price</p>
          <span className="text-[16px] leading-7 lg:text-[22px] lg:leading-8 text-headingColor font-bold">
            500 BDT
          </span>
        </div>

        <div className="mt-[30px]">
          <p className="text__para mt-0 font-semibold text-headingColor">
            Available Time Slots:
          </p>

          <ul className="mt-3">
            <li className="flex items-center justify-between mb-2">
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                Sunday
              </p>
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                4:00 PM - 8:00 PM
              </p>
            </li>

            <li className="flex items-center justify-between mb-2">
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                Monday
              </p>
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                4:00 PM - 8:00 PM
              </p>
            </li>

            <li className="flex items-center justify-between mb-2">
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                Tuesday
              </p>
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                4:00 PM - 8:00 PM
              </p>
            </li>

            <li className="flex items-center justify-between mb-2">
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                Wednesday
              </p>
              <p className="text-[15px] leading-6 text-textColor font-semibold">
                4:00 PM - 8:00 PM
              </p>
            </li>
          </ul>

          <button className="btn px-2 w-full rounded-md">
            Book Appointment
          </button>
        </div>
      </div>
    </>
  );
};

export default SidePanel;
