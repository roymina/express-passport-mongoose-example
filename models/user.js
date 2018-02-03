/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:20:04 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 13:46:49
 * @Description: User领域类
 * 由于passport和user类紧密结合，所以直接写在一起好点
 * 否则应该分开写
  */


const mongoose = require('mongoose')
const Schema = mongoose.Schema
const passportLocalMongoose = require('passport-local-mongoose')
const User = new Schema({
    username: String,
    password: String,
    gender: Boolean//可随意添加字段
});
User.plugin(passportLocalMongoose)

module.exports = mongoose.model('User', User)