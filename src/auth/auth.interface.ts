import { User } from '@prisma/client';

export interface ReturnUserWithJwt extends User {
  accessToken: string;
}
