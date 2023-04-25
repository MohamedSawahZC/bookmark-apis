import { Controller, Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";
import { PrismaModule } from "src/prisma/prisma.module";
import { I18nContext } from "nestjs-i18n";
import { JwtModule } from "@nestjs/jwt";
import { JwtStrategy } from "./strategy";


@Module({
imports : [PrismaModule,JwtModule.register({

})],
controllers:[AuthController],
providers : [AuthService,JwtStrategy]
})

export class AuthModule {}
