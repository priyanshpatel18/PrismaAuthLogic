import prisma from "../../../../db/index";
import { generateJWT } from "../../../../lib/auth";
import axios from "axios";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  // Validate Request
  const { email } = await request.json();
  if (!email || typeof email !== "string") {
    return {
      message: "Invalid email",
      status: 400,
    };
  }

  // Check if User exists
  const userExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!userExists) {
    return NextResponse.json({
      status: 400,
      message: "User does not exist",
    });
  }

  // Send Mail and store the response
  const { data } = await axios.post("http://localhost:3000/api/auth/sendMail", {
    email: userExists.email,
    forgotFlag: true,
  });
  if (data.status !== 200) {
    return NextResponse.json({
      status: 400,
      message: "Something went wrong",
    });
  }

  // Set the Cookie if the OTP is sent
  cookies().set(
    "userDoc",
    generateJWT({
      id: userExists.id,
      email: userExists.email,
    })
  );

  // Send Response
  return NextResponse.json({
    status: 200,
    message: data.message,
  });
}
