/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:25:57 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 14:18:56
 * @Description: passport定义
  */
const passport = require('passport')
//使用passport本地策略
const LocalStrategy = require('passport-local').Strategy

const User = require('../models/user')

module.exports = (app) => { 

    passport.use(new LocalStrategy(User.authenticate()))
    passport.serializeUser(User.serializeUser())
    passport.deserializeUser(User.deserializeUser())
    //使用express session
    app.use(require('express-session')({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: false
    }))

    //启用passport
    app.use(passport.initialize())
    //使用session验证
    app.use(passport.session())
    //由于passport在其它租间还要使用（router），将其返回
    return passport
  
}