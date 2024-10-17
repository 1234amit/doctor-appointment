import React from "react";
import { formatedDate } from "../../utills/formatedDate";

const DoctorAbout = () => {
  return (
    <>
      <div>
        <h3 className="text-[20px] leading-[30px] text-headingColor font-semibold flex items-center gap-2">
          About of
          <span className="text-blue-400 font-bold text-[24px] leading-9">
            Dr. Devid Headly
          </span>
        </h3>

        <p className="text__para">
          Lorem, ipsum dolor sit amet consectetur adipisicing elit. Dolor,
          rerum. Eaque dicta, adipisci cupiditate praesentium sequi unde
          similique odio, tempora explicabo esse rerum? Officiis placeat
          repellendus quae, vero earum ducimus quas aliquam libero animi, enim
          maxime rem et illo recusandae.
        </p>
      </div>
      <div className="mt-12">
        <h3 className="text-[20px] leading[30px] text-headingColor font-semibold">
          Education
        </h3>
        <ul className="pt-4 md:p-5">
          <li className="flex flex-col sm:flex-row sm:justify-between sm:items-end md:gap-5 mb-[30px]">
            <div className="">
              <span className="text-blue-400 text-[15px] leading-6 font-semibold">
                {formatedDate("09-13-2010")}
              </span>
              <p className="text-[16px] leading-6 font-medium">PHD in surjon</p>
            </div>

            <p>New Apollo Hospital, New York </p>
          </li>

          <li className="flex flex-col sm:flex-row sm:justify-between sm:items-end md:gap-5 mb-[30px]">
            <div className="">
              <span className="text-blue-400 text-[15px] leading-6 font-semibold">
                {formatedDate("12-04-2010")}
              </span>
              <p className="text-[16px] leading-6 font-medium">PHD in surjon</p>
            </div>

            <p>New Apollo Hospital, New York </p>
          </li>
        </ul>
      </div>

      <div className="mt-12">
        <h3 className="text-[20px] leading-[30px] text-headingColor font-semibold">
          Experience
        </h3>

        <ul className="grid sm:grid-cols-2 gap-[30px] pt-4 md:p-5">
          <li className="p-4 rounded bg-[#fff9ea]">
            <span className="text-yellow-300 text-[15px] leading-6 font-semibold">
              {formatedDate("09-13-2010")}
            </span>
            <p className="text-[16px] leading-6 font-medium">Sr. Sarjon</p>
            <p>New Apollo Hospital, New York </p>
          </li>

          <li className="p-4 rounded bg-[#fff9ea]">
            <span className="text-yellow-300 text-[15px] leading-6 font-semibold">
              {formatedDate("06-13-2020")}
            </span>
            <p className="text-[16px] leading-6 font-medium">Sr. Sarjon</p>
            <p>formatted hospital, New York </p>
          </li>
        </ul>
      </div>
    </>
  );
};

export default DoctorAbout;
