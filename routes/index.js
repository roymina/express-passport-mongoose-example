/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:18:21 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 14:05:14
 * @Description: 路由定义
  */
const express = require('express')
const router = express.Router()
const User = require('../models/user')
module.exports = (app,passport) => {
    router.get('/', function (req, res) {
        res.render('index', { user: req.user });
    })
    
    router.get('/register', function (req, res) {
        res.render('register', {})
    })
    
    router.post('/register', function (req, res) {
        User.register(new User({ username: req.body.username }), req.body.password, function (err, user) {
            if (err) {
                return res.render('register', { user: user })
            }
    
            passport.authenticate('local')(req, res, function () {
                res.redirect('/')
            })
        })
    })
    
    router.get('/login', function (req, res) {
        res.render('login', { user: req.user })
    })
    
    router.post('/login', passport.authenticate('local'), function (req, res) {
        res.redirect('/')
    })
    
    router.get('/logout', function (req, res) {
        req.logout()
        res.redirect('/')
    });
    app.use('/',router)
}

 