import { useState } from "react";

const ScrapeComponent = () => {
  const [url, setUrl] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch("http://localhost:5000/api/scrape", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      console.log(response.body)
      if (!response.ok) {
        throw new Error("Failed to fetch data");
      }

      const result = await response.json();
      setData(result);
      setError("");
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Enter URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button type="submit">Scrape</button>
      </form>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
};

export default ScrapeComponent;
