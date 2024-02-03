import Express from "express";
import mysql from "mysql";
import cors from "cors";
import cookieParser from "cookie-parser";
import Jwt, {decode} from "jsonwebtoken";
import path from "path";
import bcrypt from "bcrypt";


let app = Express();
app.use(Express.json());
app.use(
  cors({
      origin: ['http://localhost:3000'],
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

app.use(cookieParser())
let db = mysql.createConnection({
 host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DBNAME,
});


app.post("/login", (req, res) => {
  const sql = 'SELECT * FROM users WHERE email =?';
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: err });

    if (data.length > 0) {
bcrypt.compare(req.body.password.toString(),data[0].password,(err,response)=>{
    if (err) return res.json({Error:"errour for hashing password"})
    if (response){
        let name=data[0].name;
        let email=data[0].email;

        const token=Jwt.sign({name,email},"jwt-secret-key",{expiresIn:'1d'})
        res.cookie('token',token)
        return res.json({ Status: "success" });
    }
    else {
        return res.json({ Error: "Invalid Email or Password" });

    }
})


    } else {
        return res.json({ Error: "Invalid Email or Password" });

    }
  });
});
const verifyuser=(req,res,next)=>{
    let token = req.cookies.token
    if (!token){
         return res.json({Error:"tou are note authentication"})

    }else {
        Jwt.verify(token,"jwt-secret-key",(err,decode)=>{
            if (err){
                return res.json({Error:"token is not ivalid"})
            }else{
                req.name=decode.name;
                req.email=decode.email;

                next();
            }
        })
    }
}
app.get('/',verifyuser,(req,res)=>{
return res.json({Status:"Success",name:req.name,email:req.email})
})
app.post("/register",(req,res)=>{
    let date_ob = new Date();
const sql= "INSERT INTO users (`name`,`email`,`password`,`created_at`) VALUES (?)";
bcrypt.hash(req.body.password,10,(err,hash)=>{
   if (err) return res.json({Error:"errour for hashing password"})
    const values=[
        req.body.username,
        req.body.email,
        hash,
        date_ob

    ]
    db.query(sql,[values],(err, result)=>{
        if (err) return res.json({ Error: "Invalid Email or Password" });

        return res.json({Status:"grewart"})

    })
})



})
app.get("/logout",(req,res)=>{
    res.clearCookie('token');
    return res.json({Status:"Success"})


})

app.listen(8081, () => {
  console.log("server is running on port 8081");
});
