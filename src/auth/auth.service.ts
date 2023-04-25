import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt/dist';
import { ConfigService } from '@nestjs/config/dist/config.service';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    try {
      //1) Generate the hashed password
      const hash = await argon.hash(dto.password);
      //2) save the new user to the database
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      //3) return the saved user
      return this.signToken(user.id,user.email);
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException(
          'Invalid credentials',
        );
      }
      throw error;
    }
  }
  async login(dto: AuthDto) {
    //1) Find use
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    //2) If there is no user
    if (!user) {
      throw new ForbiddenException(
        'Invalid credentials',
      );
    }
    //3) Compare password
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );
    //4) If not password matches
    if (!pwMatches) {
      throw new ForbiddenException(
        'Invalid credentials',
      );
    }

    //5) Send the user
    delete user.hash;
    return this.signToken(user.id,user.email);
  }

  async signToken(userId: number, email: string) : Promise<{token:string}> {
    const payload = {
      sub: userId,
      email,
    };
    const token : string = await this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret:this.config.get('JWT_SECRET'),
      });
    return {
        token,
    }
  }
}
