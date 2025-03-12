import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import ConsolidatedData from "./pages/ConsolidatedData";
<<<<<<< Updated upstream
=======
import ThreatIntelForm  from "./pages/ThreatIntelForm";
>>>>>>> Stashed changes

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/consolidated" element={<ConsolidatedData />} />
<<<<<<< Updated upstream
=======
      <Route path="/submit_url" element={<ThreatIntelForm />} />
>>>>>>> Stashed changes
    </Routes>
  );
};

export default App;
