import { Injectable } from '@nestjs/common';
import { Users } from 'src/interfaces/users/users.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {

  // In-memory user storage without any DB
  private users: Users[] = [];

  async findByEmail(email: string): Promise<Users | undefined> {
    return this.users.find(user => user.email === email);
  }

  async create(user: Omit<Users, 'id'>): Promise<Users> {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser: Users = {
      ...user,
      id: Date.now(), // Generate unique ID
      password: hashedPassword,
    };
    this.users.push(newUser);
    return newUser;
  }
  
}
