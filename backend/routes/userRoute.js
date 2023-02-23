const express = require('express');
const { registerUser, loginUser, logout, getUser, loginStatus, updateUser, changePassword } = require('../controllers/userController');
const protect = require('../middleWare/authMiddleware');
const router = express.Router();


router.post("/register",registerUser);
router.post("/login", loginUser);
router.get("/logout", logout);
router.get("/getuser",protect,getUser);
router.get("/loggedin",loginStatus);
router.patch("/updateuser",protect,updateUser);
router.patch("/changepassword",protect,changePassword);
/*
PATCH is a method of modifying resources where the 
client sends partial data that is to be updated without 
modifying the entire data.
*/
module.exports = router