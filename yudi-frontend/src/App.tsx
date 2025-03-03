import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import ConsolidatedData from "./pages/ConsolidatedData";

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/consolidated" element={<ConsolidatedData />} />
    </Routes>
  );
};

export default App;
