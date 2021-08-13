import { compare } from "bcryptjs";
import { sign }  from "jsonwebtoken"
import { inject, injectable } from "tsyringe";
import { IUsersRepository } from "../../repositories/IUsersRepository";


interface IRequest {
    email: string;
    password: string;
}

interface IResponse {
    user: {
        name: string,
        email: string
    },
    token: string
}

@injectable()
class AuthenticateUserUseCase{

    constructor(
        @inject("UsersRepository")
        private usersRepository: IUsersRepository
    ){}

    async execute({email,password}: IRequest): Promise<IResponse>{
        // usuario existe
        const user = await this.usersRepository.findByEmail(email)

        if(!user){
            throw new Error("Email or Password Incorrect");
            
        }
        //senha correta
        const passwordMatch = await compare(password, user.password)

        if(passwordMatch){
            throw new Error("Email or Password Incorrect");
            
        }

        //gerar JWT
        const token = sign({}, "e56a5140110e6ed6549ba6ac973a3286", {
            subject: user.id,
            expiresIn: "1d"
        });

        return {
            user,
            token,
        }
    }
}

export { AuthenticateUserUseCase }