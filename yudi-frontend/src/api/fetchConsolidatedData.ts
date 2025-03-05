import apiClient from "./apiClient";

export const fetchConsolidatedData = async () => {
  try {
    const response = await apiClient.get("/api/consolidated-data");
    return response.data;
  } catch (error) {
    console.error("Error fetching data:", error);
    throw error;
  }
};

