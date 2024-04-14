/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require('bcrypt')
const { SECRET_KEY} = require('../config')
const jwt =require('jsonwebtoken');
const User = require("../models/user");


router.post('/login',async(req,res,next)=>{
    try{
        let {username,password}= req.body
        if(await User.authenticate(username,password)){
            const token =jwt.sign({username},SECRET_KEY)
            User.updateLoginTimestamp(username)
            return res.json({message:`Logged in`,token})
        }else{
            throw new ExpressError("Invalid username/password",400)
          }
    }catch(e){
        return next(e)
    }
})
/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register',async(req,res,next)=>{
    try{
        console.log("im here")
        const {username}= await User.register(req.body)
        const token =jwt.sign({username},SECRET_KEY)
        User.updateLoginTimestamp(username)
        return res.json({message:`User registered`,token})

    }catch(e){
        return next(e)
    }
})
module.exports=router