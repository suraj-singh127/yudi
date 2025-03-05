import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import ConsolidatedData from "./pages/ConsolidatedData";
import ThreatIntelForm  from "./pages/ThreatIntelForm";

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/consolidated" element={<ConsolidatedData />} />
      <Route path="/submit_url" element={<ThreatIntelForm />} />
    </Routes>
  );
};

export default App;
