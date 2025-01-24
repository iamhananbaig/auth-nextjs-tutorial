import db from "./db/db";
import { executeAction } from "./executeAction";
import { schema } from "./schema";
import * as argon2 from "argon2";

function titleCase(str: string) {
  return str.toLowerCase().replace(/\b\w/g, (s) => s.toUpperCase());
}

const signUp = async (formData: FormData) => {
  return executeAction({
    actionFn: async () => {
      const name = formData.get("name");
      const email = formData.get("email");
      const password = formData.get("password");
      const validatedData = schema.parse({ name, email, password });
      const pwhash = await argon2.hash(validatedData.password as string);
      await db.user.create({
        data: {
          name: titleCase(name as string),
          email: validatedData.email.toLowerCase(),
          password: pwhash,
        },
      });
    },
  });
};

export { signUp };
