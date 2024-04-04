import { Entity, BaseEntity, PrimaryGeneratedColumn, Column, ManyToOne } from "typeorm"
import User from "./user.entity"

@Entity()
export default class Phone extends BaseEntity {
    @PrimaryGeneratedColumn()
    id!: number

    @Column()
    number!: string

    @Column({ name: 'user_id' })
    userId!: number

    @ManyToOne(() => User, user => user.phone)
    user!: User
}
