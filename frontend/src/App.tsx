import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import AiConfiguration from "./pages/AiConfiguration";
import AiPlayground from "./pages/AiPlayground";
import UsageLogs from "./pages/UsageLogs";
import Tools from "./pages/Tools";
import Findings from "./pages/Findings";

export default function App() {
  return (
    <>
      <nav className="sidebar">
        <div className="brand">CYBERHUNTER AI</div>
        <div className="brand-sub">by Nastain</div>
        <NavLink to="/" end>Dashboard</NavLink>
        <NavLink to="/scan">Scan Target</NavLink>
        <NavLink to="/tools">Recon Tools</NavLink>
        <NavLink to="/findings">Findings Database</NavLink>
        <NavLink to="/ai-config">AI Configuration</NavLink>
        <NavLink to="/ai-playground">AI Playground</NavLink>
        <NavLink to="/usage-logs">Usage Logs</NavLink>
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/ai-config" element={<AiConfiguration />} />
          <Route path="/ai-playground" element={<AiPlayground />} />
          <Route path="/usage-logs" element={<UsageLogs />} />
        </Routes>
      </main>
    </>
  );
}
