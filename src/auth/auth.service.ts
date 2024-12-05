import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { Users } from 'src/interfaces/users/users.interface';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { ConflictException, UnauthorizedException } from '@nestjs/common'; // Import UnauthorizedException

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // Validating the user during login (returns user data or null if invalid)
  async validateUser(
    email: string,
    password: string,
  ): Promise<Omit<Users, 'password'> | null> {
    const user = await this.usersService.findByEmail(email);

    // If user is found and password matches, return user data without password
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...result } = user; // Remove password from the response
      return result; // Return the rest of the user data (including surname)
    }

    // Throw an error if credentials are invalid
    throw new UnauthorizedException('Invalid credentials');
  }

  // Login method: If credentials are valid, generate a JWT; if invalid, throw UnauthorizedException
  async login(user: Omit<Users, 'password'>) {
    const payload = { email: user.email, sub: user.id, surname: user.surname };

    // Access the secret key from the .env file using configService
    const secretKey = this.configService.get<string>('SECRET_KEY');

    return {
      message: 'User successfully logged in',
      responseCode: 200,
      surname: user.surname, // Include surname in the response
      access_token: this.jwtService.sign(payload, {
        secret: secretKey,
      }),
    };
  }

  // Sign up method with custom success message and responseCode
  async signup({
    rsaPin,
    surname,
    email,
    password,
    confirmPassword,
  }: Omit<Users, 'id'>): Promise<any> {
    // Validate email format
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    if (!emailRegex.test(email)) {
      throw new ConflictException('Invalid email format');
    }

    // Validate password and confirm password match
    if (password !== confirmPassword) {
      throw new ConflictException('Password and confirm password do not match');
    }

    // Validate password length
    if (password.length < 8) {
      throw new ConflictException(
        'Password must be at least 8 characters long',
      );
    }

      // Validate RSA pin is exactly 12 digits
      const rsaPinRegex = /^\d{12}$/;  // Ensures the pin is exactly 12 digits
      if (!rsaPinRegex.test(rsaPin)) {
        throw new ConflictException('RSA Pin must be a 12-digit number');
      }

        // Validate surname
    if (surname === '' || surname.length < 2) {
      throw new ConflictException('Enter valid surname');
    }

    const existingUser = await this.usersService.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    const newUser = await this.usersService.create({
      rsaPin,
      surname,
      email,
      password,
      confirmPassword,
    });

    const { password: _, ...result } = newUser; // here ... remove the password from the response for security reasons

    // Returning a custom response
    return {
      message: 'User successfully created',
      responseCode: 200,
      data: result,
    };
  }
}
