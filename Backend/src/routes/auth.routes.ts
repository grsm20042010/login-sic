import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

const auth_router = Router();

interface CadastroBody {
  nome: string;
  email: string;
  senha: string;
}

interface LoginBody {
  email: string;
  senha: string;
}

auth_router.post("/cadastrar", async (req, res) => {
  try {
    const body: CadastroBody = req.body;

    if (!body.nome || !body.email || !body.senha) {
      return res.status(400).json({
        type: "ERROR",
        message: "Preencha todos os campos obrigatórios",
      });
    }

    const existe_user =
      true &&
      (await prisma.user.findUnique({
        where: {
          email: body.email,
        },
      }));

    if (existe_user) {
      return res.status(409).json({
        type: "ERROR",
        message: "Este email já está cadastrado",
      });
    }

    let senha_hash = await bcrypt.hash(body.senha, 10);

    const new_user = await prisma.user.create({
      data: {
        nome: body.nome,
        email: body.email,
        senha: senha_hash,
      },
      select: {
        id: true,
        email: true,
        nome: true,
      },
    });

    const access_token = jwt.sign({ id: new_user.id }, process.env.JWT_SECRET, {
      expiresIn: "5m",
    });

    return res.status(201).json({
      type: "SUCESS",
      message: "Cadastro realizado com sucesso",
      access_token,
      usuario: new_user,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "ERROR",
      message: "Erro interno de servidor",
    });
  }
});

auth_router.post("/login", async (req, res) => {
  const body: LoginBody = req.body;

  if (!body.email || !body.senha) {
    return res.status(400).json({
      type: "ERROR",
      message: "Preencha todos os campos obrigatórios",
    });
  }

  const user = await prisma.user.findUnique({
    where: { email: body.email },
    select: {
      id: true,
      nome: true,
      email: true,
      senha: true,
    },
  });

  if (!user) {
    return res.status(401).json({
      type: "ERROR",
      message: "E-mail ou senha inválidos",
    });
  }

  let senha_correta = await bcrypt.compare(body.senha, user.senha);

  if (!senha_correta) {
    return res.status(401).json({
      type: "ERROR",
      message: "E-mail ou senha inválidos",
    });
  }

  const { senha: _, ...user_no_password } = user;

  const access_token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
    expiresIn: "5m",
  });

  return res.status(201).json({
    type: "SUCESS",
    message: "Login realizado com sucesso",
    access_token,
    usuario: user_no_password,
  });
});

auth_router.post("/refresh", async (req, res) => {});
auth_router.post("/logout", async (req, res) => {});

export { auth_router };
