import prisma from "../../../../db/index";
import { verifyJWT } from "../../../../lib/auth";
import { genSalt, hash } from "bcrypt";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  // Validate Request
  const { password } = await request.json();
  if (!password || typeof password !== "string") {
    return NextResponse.json({
      message: "Invalid password",
      status: 400,
    });
  }

  // Get Payload from the Token
  const userDoc = cookies().get("userDoc")?.value || "";
  const decodedToken = verifyJWT(userDoc);
  if (
    !decodedToken.payload ||
    !decodedToken ||
    !decodedToken.payload.email ||
    !decodedToken.payload.id
  ) {
    return NextResponse.json({
      message: "Invalid Token",
      status: 400,
    });
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
    return NextResponse.json({
      message: "User does not exist",
      status: 400,
    });
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
    return NextResponse.json({
      message: "Something went wrong",
      status: 400,
    });
  }
  // Delete Token after Successful Update
  cookies().delete("userDoc");

  // Send Response
  return NextResponse.json({
    message: "Password Reset Successfully",
    status: 400,
  });
}
