/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:35:36 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 13:56:55
 * @Description: middlware统一归放
  */
const path = require('path')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const db = require('./utilis/db')
const errorHandler = require('./utilis/errorHandler')
const passport = require('./utilis/passport')
const router = require('./routes')

module.exports = (app) => {
    app.set('views', path.join(__dirname, 'views'))
    app.set('view engine', 'jade')

    app.use(bodyParser.json())
    app.use(bodyParser.urlencoded({ extended: false }))
    app.use(cookieParser())

    db.conn()    
    router(app,passport(app))
    errorHandler(app)

    const server = app.listen(3000, function () {
        const host = server.address().address
        const port = server.address().port
        console.log('Example app listening at http://%s:%s', host, port)
    })
}