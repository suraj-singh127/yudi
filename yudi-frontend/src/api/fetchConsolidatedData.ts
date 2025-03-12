import apiClient from "./apiClient";

export const fetchConsolidatedData = async () => {
  try {
<<<<<<< Updated upstream
    const response = await apiClient.get("/consolidated-data");
=======
    const response = await apiClient.get("/api/consolidated-data");
>>>>>>> Stashed changes
    return response.data;
  } catch (error) {
    console.error("Error fetching data:", error);
    throw error;
  }
};
<<<<<<< Updated upstream
=======

>>>>>>> Stashed changes
