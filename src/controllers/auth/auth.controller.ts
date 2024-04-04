import { Request, Response} from 'express'
import bcrypt from 'bcrypt'
import User from '../../models/user.entity'
import Token from '../../models/token.entity'

export default class AuthController {
    static async store (req: Request, res: Response){
        const {name,email,password,phone} = req.body

        if(!name) return res.status(400).json({error: "Nome obrigatório"})
        if(!email) return res.status(400).json({error: "Email obrigatório"})
        if(!password) return res.status(400).json({error: "Senha obrigatória"})
        if(!phone) return res.status(400).json({error: "Telefone obrigatório"})

          try {
            const user = new User()
            user.name = name
            user.email = email
            user.phone = phone // Salvando o telefone

            user.password = bcrypt.hashSync(password,10)
            await user.save()

            return res.json({
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone // Retornando o telefone no response
            })
        } catch (error) {
            console.error(error)
            return res.status(500).json({ error: 'Erro interno do servidor' })
        }
    }

    static async login (req: Request, res: Response) {
        const { email, password, phone } = req.body // Adicionando a opção de login com telefone

        try {
            let user;

            if(!email && !phone) return res.status(400).json({error: 'Email ou telefone é obrigatório!'})

            if (email) {
                user = await User.findOneBy({email})
            } else {
                user = await User.findOneBy({phone})
            }

            if(!user) return res.status(401).json({error: 'Usuário não encontrado!'})

            const passwCheck = bcrypt.compareSync(password, user.password)
            if(!passwCheck) return res.status(401).json({error: 'Senha inválida!'})

            await Token.delete({user: {id: user.id}})

            const token = new Token()
            const stringRand = Math.random().toString(36)
            token.token = bcrypt.hashSync(stringRand,1).slice(-20)
            token.expiresAt = new Date(Date.now() + 60 * 60 * 1000)
            token.refreshToken = bcrypt.hashSync(stringRand+2,1).slice(-20)
            token.user = user
            await token.save()

            return res.json ({
                token: token.token,
                expiresAt: token.expiresAt,
                refreshToken: token.refreshToken
            })
        } catch (error) {
            console.error(error)
            return res.status(500).json({ error: 'Erro interno do servidor' })
        }
    }
    static async refresh(req: Request, res: Response) {
      const { authorization } = req.headers
  
      if (!authorization) return res.status(400).json({ error: 'O refresh token é obrigatório' })
  
      try {
          const token = await Token.findOneBy({ refreshToken: authorization })
          if (!token) return res.status(401).json({ error: 'Refresh token inválido' })
  
          if (token.expiresAt < new Date()) {
              await token.remove()
              return res.status(401).json({ error: 'Refresh token expirado' })
          }
  
          const stringRand = Math.random().toString(36)
          token.token = bcrypt.hashSync(stringRand, 1).slice(-20)
          token.refreshToken = bcrypt.hashSync(stringRand + 2, 1).slice(-20)
          token.expiresAt = new Date(Date.now() + 60 * 60 * 1000)
          await token.save()
  
          return res.json({
              token: token.token,
              expiresAt: token.expiresAt,
              refreshToken: token.refreshToken
          })
      } catch (error) {
          console.error(error)
          return res.status(500).json({ error: 'Erro interno do servidor' })
      }
  }
    static async logout (req: Request, res: Response) {
        const { authorization } = req.headers
        
        if (!authorization) return res.status(400).json({ error: 'O token é obrigatório' })
    
        const userToken = await Token.findOneBy({ token: authorization })
        if (!userToken) return res.status(401).json({ error: 'Token inválido' })
    
        await userToken.remove()
    
        return res.status(204).json()
      }
    
}