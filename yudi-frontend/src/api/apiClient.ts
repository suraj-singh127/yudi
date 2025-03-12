import axios from "axios";
<<<<<<< Updated upstream

const apiClient = axios.create({
  baseURL: "http://127.0.0.1:5000/api",
=======
const API_BASE_URL = "http://localhost:5000/";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
>>>>>>> Stashed changes
  headers: {
    "Content-Type": "application/json",
  },
});

<<<<<<< Updated upstream
export default apiClient;
=======
export default apiClient;
>>>>>>> Stashed changes
