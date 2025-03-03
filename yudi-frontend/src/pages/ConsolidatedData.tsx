import { useEffect, useState } from "react";
import { fetchConsolidatedData } from "../api/fetchConsolidatedData";

const ConsolidatedData = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchConsolidatedData()
      .then((result) => {
        setData(result);
        setLoading(false);
      })
      .catch(() => {
        setError("Failed to fetch data");
        setLoading(false);
      });
  }, []);

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div className="p-6">
      <h2 className="text-xl font-bold">Consolidated Threat Intelligence Data</h2>
      <pre className="bg-gray-200 p-4 rounded-md">{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
};

export default ConsolidatedData;
