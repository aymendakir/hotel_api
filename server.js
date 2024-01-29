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
    origin: "http://localhost:3000",
    methods: ["GET,POST,PUT,OPTION"],
    credentials: true,
  })
);
app.use(cookieParser())
let db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "laravel",
});


app.post("/login", (req, res) => {
  const sql = 'SELECT * FROM users WHERE email =?';
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "server side error" });

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
        return res.json({ Error: "password not match" });

    }
})


    } else {
      return res.status(401).send("Invalid Email or Password");
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
        if (err) return res.json({Error:err})

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