import apiClient from "./apiClient";

export const fetchConsolidatedData = async () => {
  try {
    const response = await apiClient.get("/consolidated-data");
    return response.data;
  } catch (error) {
    console.error("Error fetching data:", error);
    throw error;
  }
};
