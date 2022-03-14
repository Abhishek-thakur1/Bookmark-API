import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService){}

    async signup(dto: AuthDto) { 
        // generate the password..
        const hash = await argon.hash(dto.password)
        // save the new user in Db...
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });

            return this.signToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException("Credentials not available!")
                }
            }
            throw error;
            
        }
    }
    
    async signin(dto: AuthDto) { 
        
        // find user by email..
        const user = await this.prisma.user.findUnique({ 
            where: {
                email: dto.email
            }
        })

        // if user does not exist, throw exception...
        if(!user) throw new ForbiddenException('Credential not available!')

        // compare password...
        const passMatch = await argon.verify(
            user.hash,
            dto.password
        )

        // if password does not match, throw exception...
        if(!passMatch) throw new ForbiddenException('Password does not match!')

        // send back user...
        return this.signToken(user.id, user.email);
    }

    signToken(userId: number, email: string): Promise<string> {
        const payload  = {
            sub: userId, 
            email
        }
        const secret = this.config.get('JWT_SECRET')
        return this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        })
    }
    
}