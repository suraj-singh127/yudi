import { Link } from "react-router-dom";

const Home = () => {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">Threat Intelligence Dashboard</h1>
      <Link to="/consolidated" className="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded">
        View Consolidated Data
      </Link>
    </div>
  );
};

export default Home;
