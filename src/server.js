import "dotenv/config";
import express from "express";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const app = express();
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
const port = 3333;

app.use(express.json());

const verifyJWT = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acesso negado, token não fornecido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.KEY_JWT);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Token inválido" });
  }
};

app.get("/filmes", verifyJWT, async (req, res) => {
  const filmes = await prisma.filme.findMany();
  res.status(200).json(filmes);
});

app.get("/filmes/:id", verifyJWT, async (req, res) => {
  const { id } = req.params;
  const filme = await prisma.filme.findUnique({ where: { id: id } });
  res.status(200).json(filme);
});

app.post("/filmes", verifyJWT, async (req, res) => {
  const { titulo, produtora, genero, alugado } = req.body;
  const newFilme = await prisma.filme.create({
    data: { titulo, produtora, genero, alugado },
  });
  res.status(201).json(newFilme);
});

app.put("/filmes/:id", verifyJWT, async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;
  const updatedFilme = await prisma.filme.update({
    where: { id: id },
    data: updateData,
  });
  res.status(200).json(updatedFilme);
});

app.delete("/filmes/:id", verifyJWT, async (req, res) => {
  const { id } = req.params;
  await prisma.filme.delete({ where: { id: id } });
  res.status(200).json({ message: "Filme deletado com sucesso!" });
});

app.post("/seguranca/register", async (req, res) => {
  const { nome, email, login, senha } = req.body;

  const hashedPassword = await bcrypt.hash(senha, 10);
  const newUser = await prisma.usuario.create({
    data: {
      nome,
      email,
      login,
      senha: hashedPassword,
    },
  });

  res.status(201).json(newUser);
});

app.post("/seguranca/login", async (req, res) => {
  const { login, senha } = req.body;

  const user = await prisma.usuario.findUnique({ where: { login } });

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  const isPasswordValid = await bcrypt.compare(senha, user.senha);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Senha inválida" });
  }

  const token = jwt.sign(
    { id: user.id, login: user.login },
    process.env.KEY_JWT,
    { expiresIn: "1h" }
  );

  res.status(200).json({ token });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
