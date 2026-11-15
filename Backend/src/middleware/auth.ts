import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface TokenDecoded {
  id: number;
}

export interface AuthRequest extends Request {
  userId?: number;
}

export function authentication(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) {
  const auth_header = req.headers.authorization;

  if (!auth_header) {
    return res.status(401).json({
      type: "ERROR",
      message: "Token não informado",
    });
  }

  const [, token] = auth_header.split(" ");

  try {
    const jwt_decoded = jwt.verify(
      token,
      process.env.JWT_SECRET,
    ) as TokenDecoded;

    req.userId = jwt_decoded.id;

    return next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({
      type: "ERROR",
      message: "Token não informado",
    });
  }
}
