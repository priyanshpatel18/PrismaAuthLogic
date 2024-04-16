import { compare } from "bcrypt";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import prisma from "../../../db";
import { generateJWT } from "../../../lib/auth";

const userSchema = z.object({
  email: z.string().email(),
  password: z.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/),
});

export async function POST(request: NextRequest) {
  try {
    // Validate Request
    const body = new URLSearchParams(await request.text());
    const bodyEmail = body.get("email");
    const bodyPass = body.get("password");
    const { email, password } = userSchema.parse({
      email: bodyEmail,
      password: bodyPass,
    });
    if (!email || !password) {
      return NextResponse.json({
        status: 400,
        message: "Invalid Credentials",
      });
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

    // Compare Password
    const passwordMatch = compare(password, userExists.password);
    if (!passwordMatch) {
      return NextResponse.json({
        status: 400,
        message: "Incorrect Password",
      });
    }
    const token = generateJWT({
      id: userExists.id,
      email: userExists.email,
    });
    await prisma.user.update({
      data: {
        token: token,
      },
      where: {
        id: userExists.id,
      },
    });

    const userObject = {
      id: userExists.id,
      email: userExists.email,
    };
    // Send Response
    return NextResponse.json({
      status: 200,
      user: userObject,
      message: "Login Successful",
    });
  } catch (error) {
    return NextResponse.json({ status: 500, message: "Internal Server Error" });
  }
}
