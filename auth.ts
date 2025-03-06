import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`
      SELECT id, email, password, name FROM users WHERE email = ${email}
    `;
    if (user.length === 0) return undefined;

    return {
      ...user[0],
      id: user[0].id.toString(), // Convertir l'ID en string
    };
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}


async function createUser(email: string, password: string): Promise<User> {
  const hashedPassword = await bcrypt.hash(password, 10);

  const [user] = await sql<User[]>`
    INSERT INTO users (email, password, name) 
    VALUES (${email}, ${hashedPassword}, ${email.split('@')[0]}) 
    RETURNING id, email, password, name
  `;

  return {
    ...user,
    id: user.id.toString(), // Convertir l'ID en string
  };
}



export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
      
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          let user = await getUser(email);
      
          if (!user) {
            console.log(`Création d'un nouvel utilisateur : ${email}`);
            user = await createUser(email, password);
          }
      
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) {
            return {
              id: user.id.toString(), // Assure que l'ID est une string
              email: user.email,
              name: user.name,
            };
          }
        }
      
        console.log('Invalid credentials');
        return null;
      }
      
    }),
  ],
});
