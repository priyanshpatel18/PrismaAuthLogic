import { sign, verify } from "jsonwebtoken";

export function generateJWT(payload: any) {
  const SECRET_KEY = process.env.SECRET_KEY || "";

  return sign({ payload }, SECRET_KEY);
}

export function verifyJWT(token: string) {
  const SECRET_KEY = process.env.SECRET_KEY || "";

  const decodedToken = verify(token, SECRET_KEY);
  if (
    !decodedToken ||
    typeof decodedToken !== "object" ||
    !decodedToken.payload
  ) {
    return { status: 400, message: "Invalid Token" };
  }

  return { status: 200, payload: decodedToken.payload };
}