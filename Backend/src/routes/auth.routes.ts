import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";
import { authentication } from "../middleware/auth";
import { refreshToken } from "firebase-admin";

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
  const body: CadastroBody = req.body;

  if (!body.nome || !body.email || !body.senha) {
    return res.status(400).json({
      type: "ERROR",
      message: "Preencha todos os campos obrigatórios",
    });
  }
  try {
    const existe_user = await prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });

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

    const expire_date = new Date();
    expire_date.setDate(expire_date.getDate() + 30);

    const new_refresh_token = await prisma.refreshToken.create({
      data: {
        token: crypto.randomUUID(),
        expiresAt: expire_date,
        userId: new_user.id,
      },
    });

    return res.status(201).json({
      type: "SUCCESS",
      message: "Cadastro realizado com sucesso",
      access_token,
      refresh_token: new_refresh_token.token,
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

  try {
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

    const expire_date = new Date();
    expire_date.setDate(expire_date.getDate() + 30);

    const new_refresh_token = await prisma.refreshToken.create({
      data: {
        token: crypto.randomUUID(),
        expiresAt: expire_date,
        userId: user.id,
      },
    });

    return res.status(200).json({
      type: "SUCCESS",
      message: "Login realizado com sucesso",
      access_token,
      refresh_token: new_refresh_token.token,
      usuario: user_no_password,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "ERROR",
      message: "Erro interno no servidor",
    });
  }
});

auth_router.post("/refresh", async (req, res) => {
  const { refresh_token } = req.body as { refresh_token?: string };

  if (!refresh_token) {
    return res.status(400).json({
      type: "ERROR",
      message: "Refresh token não informado",
    });
  }

  try {
    const refresh_token_db = await prisma.refreshToken.findUnique({
      where: { token: refresh_token },
    });

    if (!refresh_token_db) {
      return res.status(401).json({
        type: "ERROR",
        message: "Refresh token inválido.",
      });
    }

    if (new Date() > refresh_token_db.expiresAt) {
      await prisma.refreshToken.delete({ where: { id: refresh_token_db.id } });
      return res.status(401).json({
        type: "ERROR",
        message: "Sessão expirada. Faça login novamente.",
      });
    }
    const access_token = jwt.sign(
      { id: refresh_token_db.userId },
      process.env.JWT_SECRET,
      { expiresIn: "5m" },
    );

    return res.status(200).json({
      type: "SUCCESS",
      message: "Token renovado com sucesso",
      access_token,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "ERROR",
      message: "Erro interno no servidor",
    });
  }
});

auth_router.post("/logout", authentication, async (req, res) => {
  try {
    const { refresh_token } = req.body as { refresh_token?: string };

    if (!refresh_token) {
      return res.status(400).json({
        type: "ERROR",
        message: "Refresh token não informado",
      });
    }

    await prisma.refreshToken.deleteMany({
      where: { token: refresh_token },
    });

    return res.status(200).json({
      type: "SUCCESS",
      message: "Logout realizado com sucesso",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      type: "ERROR",
      message: "Erro interno no servidor",
    });
  }
});

export { auth_router };
