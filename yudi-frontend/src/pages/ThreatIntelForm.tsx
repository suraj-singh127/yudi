import { useState } from "react";
import apiClient from "../api/apiClient";

export default function IOCInputPage() {
  const [iocData, setIocData] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (event) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile(event.target.files[0]);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    const formData = new FormData();
    
    if (file) {
      formData.append("file", file);
    } else if (iocData.trim()) {
      formData.append("manual_input", iocData);
    }

    try {
      await apiClient.post("/api/manual_input", formData, {
        headers: { "Content-Type": "application/json" },
      });
      alert("Upload successful");
    } catch (error) {
      alert("Upload failed");
    }
    setLoading(false);
  };

  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
      <form onSubmit={handleSubmit} style={{ textAlign: "center", padding: "20px", border: "1px solid #ccc", borderRadius: "5px", background: "#f9f9f9" }}>
        <h3>Upload IOCs</h3>
        <p>Supports JSON, CSV, STIX, TXT</p>
        <input type="file" accept=".json,.csv,.txt,.stix" onChange={handleFileChange} /><br /><br />
        <p>Or manually enter IOCs:</p>
        <textarea value={iocData} onChange={(e) => setIocData(e.target.value)} placeholder="Paste IOCs..."></textarea><br /><br />
        <button type="submit" disabled={loading}>{loading ? "Uploading..." : "Submit"}</button>
      </form>
    </div>
  );
}
