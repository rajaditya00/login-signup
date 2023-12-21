
//auth , isStudent , isAdmin 

const jwt = require('jsonwebtoken');
require("dotenv").config();
 

exports.auth =(req, res, next) =>{
    try{
        //extract jwt token

        console.log("body", req.body.token);
        console.log("cookies", req.cookies.token);
        // console.log("body", req.header("Authorization").replace("Bearer",""));

        const token = req.body.token || req.cookies.token || req.header("Authorization").replace("Bearer","");

        if(!token){
           return res.status(401).json({
             success:false,
             message:'token mising',
           })
        }
        //verify the token
        try{
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            console.log(payload);

            // why this ?
            req.user = payload;

        }catch(error){
           return res.status(401).json({
            success:false,
            message:"token is invalide",
           });
        }
      next();

    }catch(error){
         return res.status(401).json({
            successfalse,
            message:'something went wrong,while verifying the token',
         })
    }
}

exports.isStudent = (req, res, next) =>{
    try{
        if(req.user.role !== "Student"){
            return res.status(401).json({
                success:false,
                message:'This is a protected route for students'
            });
        } 
        next();

    }catch(error){
           return res.status(500).json({
            success:false,
            message:'User role is not matching',
           }) 
    }
}

exports.isAdmin = (req,res,next) =>{
    try{
        if(req.user.role !=="Admin"){
            return res.status(401).json({
                success:false,
                message:'This is a protected route for Admin'
            });
        }
     next();

    }catch(error){
        return res.status(500).json({
            success:false,
            message:'User role is not matching',
           }) 
    }
}