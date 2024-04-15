import { z } from "zod";

export const RegisterUserSchema = z.object({
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().regex(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/),
  password: z.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/),
  profilePicture: z.any().optional(),
});
