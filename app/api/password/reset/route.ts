import prisma from "../../../../db";
import { verifyJWT } from "../../../../lib/auth";
import { genSalt, hash } from "bcrypt";
import { cookies } from "next/headers";

export async function POST(request: Request) {
  // Validate Request
  const { password } = await request.json();
  if (!password || typeof password !== "string") {
    return {
      message: "Invalid password",
      status: 400,
    };
  }

  // Get Payload from the Token
  const otpToken = cookies().get("OTPDoc")?.value || "";
  const decodedToken = verifyJWT(otpToken);
  if (
    !decodedToken.payload ||
    !decodedToken ||
    !decodedToken.payload.email ||
    !decodedToken.payload.id
  ) {
    return {
      message: "Invalid Token",
      status: 400,
    };
  }

  // Decoded Email
  const { email } = decodedToken.payload;
  // Check if User Exists
  const userExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!userExists) {
    return {
      message: "User does not exist",
      status: 400,
    };
  }

  // Update User if it exists
  const updatedUser = await prisma.user.update({
    where: {
      email,
    },
    data: {
      password: await hash(password, await genSalt(10)),
    },
  });
  if (!updatedUser) {
    return {
      message: "Something went wrong",
      status: 400,
    };
  }
  // Delete Token after Successful Update
  cookies().delete("OTPDoc");

  // Send Response
  return {
    status: 200,
    message: "Password Reset Successfully",
  };
}
