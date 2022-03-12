import { Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService){}

    async signup(dto: AuthDto) { 
        // generate the password..
        const hash = await argon.hash(dto.password)
        // save the new user in Db...
        const user = await this.prisma.user.create({ 
            data: { 
                email: dto.email,
                hash
            }
        })
        // return the saved user
        return user;
    }
    
    signin(){ 
        return { msg: "I've signed in!" };
    }
    
}