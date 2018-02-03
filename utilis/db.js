/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:18:46 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 13:34:00
 * @Description: 数据库连接
  */
const mongoose = require('mongoose') 

const conn = ()=>{
    mongoose.connect('mongodb://localhost/express4_passport');
    const db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function () {
       console.log('db connection success!')
    });
}
module.exports =  {
   conn:conn
}