## Hi I'm Ivan Eliseo 👋

[![committers.top badge](https://user-badge.committers.top/el_salvador/IvanEliseoDev.svg)](https://user-badge.committers.top/el_salvador/IvanEliseoDev)

## About me 
Hi! I'm a FullStack Jr. Developer passionate about continuous learning and exploring new technologies. I focus on solving problems through efficient software solutions, with a strong interest in Backend development and data flow analysis. While I love building robust server-side architectures, I am also highly proficient in the Frontend using React and TypeScript to deliver complete and functional user experiences.

## Stats

<!--START_SECTION:waka-->

```txt
From: 25 January 2026 - To: 19 June 2026

TypeScript   82 hrs 24 mins        ░░░░░░░░░░░░░░░▒█████████   62.10 %
JavaScript   44 hrs 15 mins        ░░░░░░░░▓████████████████   33.34 %
Bash         2 hrs 34 mins         ▓████████████████████████   01.94 %
CSS          1 hr 13 mins          ▓████████████████████████   00.92 %
JSON         28 mins               █████████████████████████   00.36 %
```

<!--END_SECTION:waka-->

## Tech Stack

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)
![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![NestJS](https://img.shields.io/badge/NestJS-E0234E?style=for-the-badge&logo=nestjs&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![Oracle](https://img.shields.io/badge/Oracle-F80000?style=for-the-badge&logo=oracle&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)

### Tools
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

import jwt from "jsonwebtoken"
import { config } from "../../../config.js"
import { studentModel } from "../../models/student/studentModel.js"
import crypto from "crypto"
import nodemailer from "nodemailer"
import bcrypt from "bcrypt"

export const recoveryStudent = {
    requestCode: async(req, res) =>{
        try {
            const {email} = req.body
            const studentFound = await studentModel.findOne({email: email})
            if(!studentFound) return res.status(404).json({status:400, message:"Student not found"})
            const code = crypto.randomBytes(3).toString("hex")
            console.log(code)
            const token = jwt.sign(
                {email: email, code: code, userType: "Student", verified: false},
                config.jwt.SECRET_KEY,
                {expiresIn: "15m"}
            )
            res.cookie("recoveryCookie", token, {maxAge: 15 * 60 * 1000})
            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth:{
                    user: config.user.USER_EMAIL,
                    pass: config.user.USER_PASSWORD
                },
                tls:{
                    rejectUnauthorized: false
                }
            })
            const mailOptions = {
                from: config.user.USER_EMAIL,
                to: email,
                subject: `Verify code to Recovery Password ${code}`,
                body: `${code}`
            }
            await transporter.sendMail(mailOptions)
            return res.status(200).json({status:200, message:"Verified code by Recovery Password send successfully", data: null})
        } catch (error) {
            console.log("Internal Server Error: ", error)
            return res.status(500).json({status:500, message:"Internal Ser ver Error - Check Server Logs", data: null})
        }
    },
    verifyRecoveryCode: async(req, res) => {
        try {
            const {codeRequest} = req.body
            if(!codeRequest) return res.status(400).json({status:400, message:"Bad Request,The verification code must not be empty.", data: null})
            const token = req.cookies.recoveryCookie 
            const decoded = jwt.verify(token, config.jwt.SECRET_KEY)
            console.log(decoded)
            if(codeRequest !== decoded.code) return res.status(400).json({status:400, message:"Invalid code - code is not same", data: null})
            const newToken = jwt.sign({email: decoded.email, userType: "Student", verified:true}, config.jwt.SECRET_KEY, {expiresIn: "15m"})
            res.cookie("recoveryCookie", newToken, {maxAge: 15 * 60 * 1000})
            return res.status(200).json({status:200, message:"Code is Verified", data: null})
        } catch (error) {
            console.log("Internal Server Error: ", error)
            return res.status(500).json({status:500, message:"Internal Ser ver Error - Check Server Logs", data: null})
        }
    },
    newPassword: async(req, res) => {
        try {
        const {newPassword, confirmedPassword} = req.body
        if(!newPassword || !confirmedPassword) return res.status(400).json({status:400, message: "new password and confirmed password It should not be empty.", data: null})
        const token = req.cookies.recoveryCookie
        const decoded =  jwt.verify(token, config.jwt.SECRET_KEY)
        console.log(decoded)
        if(!decoded.verified) return res.status(400).json({status:400, message: "The code is not verified", data: null})
        const passwordHashed = await bcrypt.hash(newPassword, 10)
        await studentModel.findOneAndUpdate({email: decoded.email}, {password: passwordHashed}, {new:true})
        res.clearCookie("recoveryCookie")
        return res.status(200).json({status:200, message:"Password Updated has successfully", data: null})
        } catch (error) {
            console.log("Internal Server Error: ", error)
            return res.status(500).json({status:500, message:"Internal Ser ver Error - Check Server Logs", data: null})
        }
    
    }
}


