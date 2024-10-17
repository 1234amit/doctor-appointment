export const formatedDate = (date, config) => {
  const defaultOption = { day: "numeric", month: "long", year: "numeric" }; // Corrected "numaric" to "numeric"
  const options = config ? config : defaultOption;

  return new Date(date).toLocaleDateString("en-US", options);
};
