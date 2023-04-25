import { Controller } from "@nestjs/common/decorators/core/controller.decorator";
import { Get,UseGuards,Req } from "@nestjs/common";
import {AuthGuard} from "@nestjs/passport"
import { Request } from "express";
import { JwtGuard } from "src/auth/guard";
import { GetUser } from "src/auth/decorators/get-user.decorator";
import { User } from "@prisma/client";

@UseGuards(JwtGuard)
@Controller('user')
export class UserController{

@Get('me')
getMe(@GetUser() user : User){
    return user;
}
}