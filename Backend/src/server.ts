import "dotenv/config";
import express from "express";
import cors from "cors";

import { auth_router } from "./routes/auth.routes";
import { authentication } from "./middleware/auth";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173", // React Web (Vite)
      "http://localhost", // APK Android (Capacitor)
      "capacitor://localhost", // App iOS (Capacitor)
    ],
  }),
);

app.use("/auth", auth_router);

app.get("/", (req, res) => {
  res.json({ mensagem: "API do SIC rodando!" });
});

app.get("/painel", authentication, (req, res) => {
  res.json({ mensagem: "painel de aluno ou prof :)" });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
