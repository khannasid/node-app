const mongoose = require("mongoose");
const bryptjs = require("bcryptjs");


const userSchema = mongoose.Schema({
    name: {
        type: String, 
        required: [true, "please add a name"]
    },
    email: {
        type: String, 
        required: [true, "please add a email"],
        unique: true,
        trim: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "Please enter a valid email"
        ]
    },
    password:{
        type: String,
        required: [true, "Please add a password"],
        minLength: [6, "Password must be up to 6 char"],
        // maxLength: [23, "Password is too long"]
    },
    photo:{
        type: String,
        required: [true, "Please add a photo"], 
        default: "https://picsum.photos/seed/picsum/200/300"
    },
    phone:{
        type: String,
        default: "+91"
    },
    bio:{
        type: String,
        maxLength: [250, "Bio must not be more than 250 char"],
        default: "bio"
    }
},{
    timestamps:true,
})

// Encrypt the password before saving in DB
userSchema.pre("save", async function(next) {
    if(!this.isModified("password")){
        return next();
    }
    
    //Hash password
    const salt = await bryptjs.genSalt(10)
    const hashedPassword = await bryptjs.hash(this.password, salt);
    this.password = hashedPassword;
    next();
})

const User = mongoose.model("User", userSchema);
module.exports = User