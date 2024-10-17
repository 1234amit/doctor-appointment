// import React, { useEffect, useRef } from "react";
// import logo from "./../../assets/images/logo.png";
// import { Link, NavLink } from "react-router-dom";
// import userImg from "./../../assets/images/avatar-icon.png";
// import { BiMenu } from "react-icons/bi";

// const Header = () => {
//   const headerRef = useRef(null);
//   const menuRef = useRef(null);

//   const handleStickyHeader = () => {
//     window.addEventListener("scroll", () => {
//       if (
//         document.body.scrollTop > 80 ||
//         document.documentElement.scrollTop > 80
//       ) {
//         headerRef.current.classList.add("sticky__header");
//       } else {
//         headerRef.current.classList.remove("sticky__header");
//       }
//     });
//   };

//   useEffect(() => {
//     handleStickyHeader();
//     return () => window.removeEventListener("scroll", handleStickyHeader);
//   }, []);

//   const toggleMenu = () => menuRef.current.classList.toggle("show__menu");

//   const navLinks = [
//     {
//       path: "/home",
//       display: "Home",
//     },
//     {
//       path: "/doctors",
//       display: "Find a Doctors",
//     },
//     {
//       path: "/Services",
//       display: "Services",
//     },
//     {
//       path: "/contact",
//       display: "Contact",
//     },
//   ];
//   return (
//     <>
//       <header className="header flex items-center" ref={headerRef}>
//         <div className="container">
//           <div className="flex items-center justify-between">
//             {/* logo start */}
//             <div>
//               <Link to="/">
//                 <img src={logo} alt="header-logo" />
//               </Link>
//             </div>

//             {/* menu start */}
//             <div className="navigation" ref={menuRef} onClick={toggleMenu}>
//               <ul className="menu flex items-center gap-[2.7rem]">
//                 {navLinks.map((link, index) => (
//                   <li key={index}>
//                     <NavLink
//                       to={link.path}
//                       className={(navClass) =>
//                         navClass.isActive
//                           ? "text-primaryColor text-[16px] leading-7 font-[600]"
//                           : "text-textColor text-[16px] leading-7 font-[500]"
//                       }
//                     >
//                       {link.display}
//                     </NavLink>
//                   </li>
//                 ))}
//               </ul>
//             </div>

//             {/* menu end */}

//             {/* nav right start */}
//             <div className="flex items-center gap-4">
//               <div className="hidden">
//                 <Link>
//                   <figure className="w-[35px] h-[35px] rounded-full cursor-pointer">
//                     <img
//                       src={userImg}
//                       alt="user-image"
//                       className="w-full rounded-full"
//                     />
//                   </figure>
//                 </Link>
//               </div>
//               <div>
//                 <Link to="/login">
//                   <button className="bg-primaryColor py-2 px-6 text-white font-[600] h-[44px] flex items-center rounded-[50px]">
//                     Login
//                   </button>
//                 </Link>
//               </div>

//               <span className="md:hidden" onClick={toggleMenu}>
//                 <BiMenu className="w-6 h-6 cursor-pointer" />
//               </span>
//             </div>
//             {/* nav right end */}
//           </div>
//         </div>
//       </header>
//     </>
//   );
// };

// export default Header;

import React, { useEffect, useRef } from "react";
import logo from "./../../assets/images/logo.png";
import { Link, NavLink } from "react-router-dom";
import userImg from "./../../assets/images/avatar-icon.png";
import { BiMenu } from "react-icons/bi";

const Header = () => {
  const headerRef = useRef(null);
  const menuRef = useRef(null);

  const handleStickyHeader = () => {
    const header = headerRef.current;
    if (!header) return; // Ensure headerRef is not null
    window.addEventListener("scroll", () => {
      if (
        document.body.scrollTop > 80 ||
        document.documentElement.scrollTop > 80
      ) {
        header.classList.add("sticky__header");
      } else {
        header.classList.remove("sticky__header");
      }
    });
  };

  useEffect(() => {
    handleStickyHeader();

    return () => window.removeEventListener("scroll", handleStickyHeader);
  }, []);

  const toggleMenu = () => {
    const menu = menuRef.current;
    if (!menu) return; // Ensure menuRef is not null
    menu.classList.toggle("show__menu");
  };

  const navLinks = [
    {
      path: "/home",
      display: "Home",
    },
    {
      path: "/doctors",
      display: "Find a Doctors",
    },
    {
      path: "/Services",
      display: "Services",
    },
    {
      path: "/contact",
      display: "Contact",
    },
  ];

  return (
    <>
      <header className="header flex items-center" ref={headerRef}>
        <div className="container">
          <div className="flex items-center justify-between">
            {/* logo start */}
            <div>
              <Link to="/">
                <img src={logo} alt="header-logo" />
              </Link>
            </div>

            {/* menu start */}
            <div className="navigation" ref={menuRef}>
              <ul className="menu flex items-center gap-[2.7rem]">
                {navLinks.map((link, index) => (
                  <li key={index}>
                    <NavLink
                      to={link.path}
                      className={(navClass) =>
                        navClass.isActive
                          ? "text-primaryColor text-[16px] leading-7 font-[600]"
                          : "text-textColor text-[16px] leading-7 font-[500]"
                      }
                    >
                      {link.display}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>

            {/* menu end */}

            {/* nav right start */}
            <div className="flex items-center gap-4">
              <div className="hidden">
                <Link>
                  <figure className="w-[35px] h-[35px] rounded-full cursor-pointer">
                    <img
                      src={userImg}
                      alt="user-image"
                      className="w-full rounded-full"
                    />
                  </figure>
                </Link>
              </div>
              <div>
                <Link to="/login">
                  <button className="bg-primaryColor py-2 px-6 text-white font-[600] h-[44px] flex items-center rounded-[50px]">
                    Login
                  </button>
                </Link>
              </div>

              <span className="md:hidden" onClick={toggleMenu}>
                <BiMenu className="w-6 h-6 cursor-pointer" />
              </span>
            </div>
            {/* nav right end */}
          </div>
        </div>
      </header>
    </>
  );
};

export default Header;
