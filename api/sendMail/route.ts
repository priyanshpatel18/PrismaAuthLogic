import otpGenerator from "otp-generator";
import prisma from "../../db";
import sendOTP from "../../utils/nodemailer";

export async function POST(email: string) {
  if (!email || typeof email !== "string") {
    return {
      message: "Invalid email",
      status: 400,
    };
  }

  const otp = otpGenerator.generate(6, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  if (
    process.env.SMTP_HOST &&
    process.env.SMTP_PORT &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
  ) {
    const { mailResponse } = await sendOTP(email, otp);

    if (mailResponse.accepted) {
      const expiresAt = new Date(new Date().getTime() + 10 * 60 * 1000);

      const newOTP = await prisma.otp.upsert({
        where: {
          email: email,
        },
        create: {
          email,
          otp,
          expiresAt,
        },
        update: {
          otp,
          expiresAt,
        },
      });
      if (!newOTP) {
        return {
          message: "Internal Server Error",
          status: 500,
        };
      }

      return {
        message: `OTP sent to ${email}`,
        status: 200,
      };
    } else {
      return {
        message: "Internal Server Error",
        status: 500,
      };
    }
  } else {
    return {
      message: "Internal Server Error",
      status: 500,
    };
  }
}
