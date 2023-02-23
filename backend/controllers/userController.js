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

// Get user Data
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if(user){
        const {_id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id,
            name, 
            email,
            photo,
            bio,
            phone
        });
    }else{
        res.status(400);
        throw new Error("User not found!");
    }
});

const loginStatus = asyncHandler(async(req, res) =>{
    
    const token = req.cookies.token;
    if(!token){
        return res.json(false);
    }
    // Need to verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if(verified){
        return res.json(true);
    }
    return res.json(false);

});

const updateUser = asyncHandler(async (req, res) =>{
    const user = await User.findById(req.user._id);
    
    if(user){
        const {name, email, photo, phone, bio} = user;
        user.email = email;
        user.name = req.body.name||name;
        user.photo = req.body.photo||photo;
        user.phone = req.body.phone||phone;
        user.bio = req.body.bio||bio;
        
        const updatedUser = await user.save()
        res.status(200).json({
            _id: updatedUser._id,
            email: updatedUser.email,
            name: updatedUser.name,
            photo: updatedUser.photo,
            phone: updatedUser.phone,
            bio: updatedUser.bio
        })
    }
    else{
        res.status(404);
        throw new Error("User not found");
    }
});

const changePassword = asyncHandler(async (req, res)=>{
    const user = await User.findById(req.user._id);

    const {oldPassword, password} = req.body;
    // if password is same as old password
    if(oldPassword === password){
        throw new Error("Old password is same as new password!");
    }
    if(!user){
        res.status(400);
        throw new Error("User not found, please signup");
    }
    //Validation
    if(!oldPassword || !password){
        res.status(400);
        throw new Error("Please input the cridentials");
    }

    // Verify old password from DB password
    const passwordIsCorred = await bryptjs.compare(oldPassword,user.password);
    /*Here as we have saved the initial password "Hash" in the User Model 
    We didnt need to encrypt the input old password and easyly use compare function
    to verify*/

    if(user && passwordIsCorred){
        user.password = password;
        await user.save();
        res.status(200).send("Password changed successfully");
    }else{
        res.status(400)
        throw new Error("Old password is incorrect");
    }
})

module.exports = {
    registerUser, loginUser,logout,getUser,
    loginStatus,updateUser,changePassword,
}