import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService){}

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

            delete user.hash;
            // return the saved user
            return user;
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
        delete user.hash
        return user;
    }
    
}