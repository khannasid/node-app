const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bryptjs = require("bcryptjs");


const generateToken = (id) => {
    return jwt.sign({id},process.env.JWT_SECRET,{expiresIn:"1d"});
}

//Register User!
const registerUser = asyncHandler(async (req, res) =>{
        const {name, email, password} = req.body;

        //Validation
        if(!name || !email || !password){
            res.status(400)
            throw new Error("Please fill all required fields")
        }
        if(password.length < 6){
            res.status(400)
            throw new Error("Password must be up to 6 char")
        }

        // check if user email already exists
        const userExist = await User.findOne({email});

        if(userExist){
            res.status(400)
            throw new Error("Email has already been registered");
        }
        
        // Create new user
        const user = await User.create({
            name,
            email,
            password,
        })
        //Generate Token
        const token = generateToken(user);        

        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly:true,
            expires:new Date(Date.now()+1000*86400),// 1 Day
            sameSite:"none",
            secure:true
        });
        if(user){
            const {_id, name, email, photo, phone, bio} = user
            res.status(201).json({
                _id, name, email, photo, phone, bio,token,
            })
        }else{
            res.status(400)
            throw new Error("Invalid user data")
        }

});

//Login User!!
const loginUser = asyncHandler(async (req, res) => {
    
    const {email, password} = req.body;

    //Validate Request
    if(!email || !password){
        res.status(400);
        throw new Error("Please add email & password");
    }

    // Chenk if User exists
    const user = await User.findOne({email});

    if(!user){
        res.status(400);
        throw new Error("User not found, Please signup");
    }

    //User exist, now check if password is correct
    const passwordIsCorred = await bryptjs.compare(password, user.password);
    
    //Generate Token
    const token = generateToken(user);        

    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly:true,
        expires:new Date(Date.now()+1000*86400),// 1 Day
        sameSite:"none",
        secure:true
    });

    if(user && passwordIsCorred){
        const {_id, name, email, photo,phone, bio} = user;
        res.status(200).json({
            _id, 
            name, 
            email,
            photo,
            phone,
            bio,
            token
        });
    }
        else{
            res.status(400);
            throw new Error("invalid input!!");
        }

});

// Logout user
const logout = asyncHandler(async (req, res)=>{
    // to logout we can delete the cookie or 
    // expire the cookie that is created while 
    // login!
    res.cookie("token","",{
        path:"/",
        httpOnly:true,
        expires: new Date(0),
        sameSite:"none",
        secure:true,
    });
    return res.status(200).json({
        message:"Successfully logged out!!"
    })
});

module.exports = {
    registerUser, loginUser,logout,
}