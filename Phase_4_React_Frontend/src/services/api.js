import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5001",
  headers: {
    "Content-Type": "application/json",
  },
});

export const analyzeHeader = async (header) => {
  const response = await API.post("/analyze", {
    header,
  });

  return response.data;
};

export default API;