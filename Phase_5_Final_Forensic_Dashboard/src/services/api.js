import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5001",
});

export const analyzeHeader = async (header) => {
  const response = await API.post("/analyze", {
    header,
  });

  return response.data;
};

export const verifyEmail = async (file) => {
  const formData = new FormData();

  formData.append("email", file);

  const response = await API.post(
    "/verify",
    formData
  );

  return response.data;
};

export default API;