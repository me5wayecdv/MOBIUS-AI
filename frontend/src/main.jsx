import React from "react";
import { createRoot } from "react-dom/client";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./styles.css";
import GraphApp from "./GraphApp.jsx";
createRoot(document.getElementById("root")).render(
  <React.StrictMode><ReactFlowProvider><GraphApp /></ReactFlowProvider></React.StrictMode>
);
