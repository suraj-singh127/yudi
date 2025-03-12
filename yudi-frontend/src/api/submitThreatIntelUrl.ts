import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

export const submitThreatIntelUrl = async (url: string) => {
  try {
    console.log("Submitting URL:", url);
    
    const response = await axios.post(
      `${API_BASE_URL}/api/scrape`,
      { url }, // ✅ Ensure JSON body is correctly formatted
      { headers: { "Content-Type": "application/json" } } // ✅ Explicitly set JSON headers
    );

    console.log("API Response:", response.data);
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      console.error("Axios Error:", error.response?.status, error.response?.data);
    } else {
      console.error("Unexpected Error:", error);
    }
    throw error;
  }
};
