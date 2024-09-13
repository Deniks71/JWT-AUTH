require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
//config JSON response
app.use(express.json());

//Models
const User = require('./models/User.js');

// Public Route
app.get('/', (req,res) => {
    res.status(200).json({msg:'Bem vindo'});
});

//Private Route 
app.get("/user/:id", checkToken, async (req,res) => {
    
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id,'-password')

    if(!user) {
        return res.status(422).json({msg: 'Usuario nao encontrado'})
    };

    res.status(200).json({user})
})

function checkToken(req,res,next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({msg: 'Acesso Negado'})
        
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next();
    } catch(err) {
        res.status(400).json({msg: 'token invalido'})
    }
}


//Register User 
app.post('/auth/register', async(req,res) => {
    const {name, email, password, confirmpassword} = req.body;

    if(!name) {
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }
    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }
    if(password !== confirmpassword) {
        return res.status(422).json({msg: 'Senhas nao conferem!'})
    }

    const userExists = await User.findOne({ email: email});

    //check if user exist
    if(userExists) {
        return res.status(422).json({msg: 'Por favor use outro email'})
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({msg: 'Usuario criado com sucesso'});
    } catch(error) {
        console.log(error)
        res.json({msg: 'aconteceu um erro'})
    }
    
});

//Login User
app.post("/auth/login", async (req,res) => {
    const {email,password} = req.body

    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }


    //Check if user exists
    const user = await User.findOne({ email: email});

    if(!user) {
        return res.status(422).json({msg: 'Usuario nao encontrado'})
    }

    //Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha inválida'});
    };

    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        },secret,
    );
    return res.status(200).json({msg: 'Autenticação realizada com sucesso', token});
    } catch(err) {
        console.log(err)
        res.json({msg: 'aconteceu um erro'})
    }
});

//Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.pkx5m.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(3000)
        console.log("Conectou ao banco")
    })
    .catch((err) => console.log(err))


