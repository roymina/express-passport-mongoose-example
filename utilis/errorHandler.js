/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:30:42 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 14:18:15
 * @Description: error handlers
  */
module.exports = (app) => {
    app.use(function(req, res, next) {
        var err = new Error('Not Found')
        err.status = 404
        next(err)
    }) 
    
    // development error handler
    // will print stacktrace
    if (app.get('env') === 'development') {
        app.use(function(err, req, res, next) {
            res.status(err.status || 500)
            res.render('error', {
                message: err.message,
                error: err
            })
        })
    }
    
    // production error handler
    // no stacktraces leaked to user
    app.use(function(err, req, res, next) {
        res.status(err.status || 500)
        res.render('error', {
            message: err.message,
            error: {}
        })
    })
}