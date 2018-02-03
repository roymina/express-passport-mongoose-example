![没有passport你哪儿也别想去](http://upload-images.jianshu.io/upload_images/1431816-7e468e999161cef4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

# 1.基础
* Passport使用不同的策略（>300种）进行授权，最常见的是本地策略，本地策略中最常见的又是用户名密码策略
```
var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;

  
  passport.use(new LocalStrategy(
    function(username, password, done) {
    try{
    //If the credentials are not valid (for example, if the password is incorrect), done should be invoked with false instead of a user to indicate an authentication failure.An additional info message can be supplied to indicate the reason for the failure. This is useful for displaying a flash message prompting the user to try again.
        if (username!='aaa') {
            return done(null, false, { message: 'Incorrect username.' });
          }
          if (password!='aaa') {
            return done(null, false, { message: 'Incorrect password.' });
          }
          //If the credentials are valid, the verify callback invokes done to supply Passport with the user that authenticated.
          return done(null, user);
    }
    catch(err){
    return done(err);
    }
    }
  ));
```
着重说一下上面的callback，也就是done()方法
- 如果验证通过，则将登陆的用户返回：`done(null,user)`
- 如果验证未通过，比如，用户名密码错误，则返回`done(null,false)`，还可以提供额外信息` done(null, false, { message: 'Incorrect password.' });`
- 如果发生异常，则`done(err)`

# 2.将passport作为express中间件
* express应用需要`passport.initialize()`来进行启动
如果打算使用基于session的验证（非SPA、浏览器最常用这种方法），需要使用`passport.session()`和`session()`中间件，（`session()`要在`passport.session()`之前声明引用），在express4.x中的写法如下：
```
var express = require('express');
var session = require("express-session");
var bodyParser = require("body-parser");
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var app = express();
app.use(express.static("public"));
app.use(session({ secret: "cats" }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;
    console.log('Example app listening at http://%s:%s', host, port);
});
```

# 3. Session
一个典型的网络应用，授权过程只有在login过程中发生，如果验证成功，服务器将建立一个session，并在浏览器端建立一个cookie.
再往后的请求都不会再次请求凭证。但浏览器有一个唯一的cookie，对应服务端相应的session。为了支持登录session验证，passport在session中对user进行序列化和反序列化：
```
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
```
注意到，只对userid进行了序列化操作，这是为了减小session体积。在接下来的请求中，这个id用来查找user，并存储在req.user。
序列化和反序列化由应用程序定义，可自由选择数据库或者objectmapper方法。这里与验证层无关。

# 4. Username & Password验证方式举例：

最广泛使用的就是用户名、密码验证方式。 [passport-local](https://github.com/jaredhanson/passport-local) 模块支持这种方式
```
var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      if (!user.validPassword(password)) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
    });
  }
));
```
代码基本和前面一样，只不过这里使用数据库查询来确定用户身份。
- 前端页面：
```html
<form action="/login" method="post">
    <div>
        <label>Username:</label>
        <input type="text" name="username"/>
    </div>
    <div>
        <label>Password:</label>
        <input type="password" name="password"/>
    </div>
    <div>
        <input type="submit" value="Log In"/>
    </div>
</form>
```
- 后端路由
使用 `authenticate() `和` local` 策略的路由
```
app.post('/login',
  passport.authenticate('local', { successRedirect: '/',
                                   failureRedirect: '/login',
                                   failureFlash: true })
);
```
后面的三个参数分别是成功跳转、失败跳转和消息闪现
消息闪现只在浏览器出现一次，然后就被销毁`阅后即焚`。当其设置为true时，错误message将会被发送到客户端：
`if (err) { return done(err); }`
前端使用`{{error.message}}`就能拿到消息

* 默认情况下passport使用`username`和`password`,也可以自由定义：
```
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'passwd'
  },
  function(username, password, done) {
    // ...
  }
));
```

# 5. login和logout方法
passport在req上暴露这两个方法，可以直接使用：
```
req.login(user, function(err) {
  if (err) { return next(err); }
  return res.redirect('/users/' + req.user.username);
});
```
login方法执行完毕后，`user`对象将会被赋值给req.user。注意` passport.authenticate()`中间件自动调用login方法。无需手动调用。需要调用此方法的时候是用户注册成功后自动登陆的场景。

```
app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
```
logout方法将清除req.user和服务端session

# 6.其它相关包
如果打算使用mongoose，`passport-local-mongoose`包（以下简称plm）是一个mongoose插件，将会简化username和password存储流程:[github](https://github.com/saintedlama/passport-local-mongoose)
使用mongoose+passport安装的典型依赖：
`npm install passport passport-local mongoose passport-local-mongoose --save`
#### 使用passport-local-mongoose
6.1 在领域类中定义 plugin：
```
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');
const User = new Schema({});
//plugin可接受option参数
User.plugin(passportLocalMongoose);

module.exports = mongoose.model('User', User);
```
你可以自由定义user类，plm将自动为其加入username、hash和salt字段，以及一些额外的方法
`User.plugin(passportLocalMongoose, options);`
> ### Main Options:
>`saltlen`: 盐长度. Default: 32
`iterations`: 哈希算法 iterations长度. Default: 25000
`keylen`: key长度. Default: 512
`digestAlgorithm`: 加密算法，Default: sha256.
`interval`: login允许间隔时间. Default: 100
`usernameField`: 自定义username字段名称. Defaults to 'username'. 比如可以改为"email".
`usernameUnique` :username字段是否唯一. Defaults to true.
`saltField`: salt字段名称. Defaults to 'salt'.
`hashField`: hash字段名称.  Defaults to 'hash'.
`attemptsField`: 用户登陆尝试次数字段名称. Defaults to 'attempts'.
`lastLoginField`: 最后登陆时间戳字段名称. Defaults to 'last'.
`selectFields`: 定义在mongodb中存储哪些字段. Defaults to 'undefined' ，默认User所有字段都存储.
`usernameLowerCase`: 是否将username字段小写处理. Defaults to 'false'.
`populateFields`:  `findByUsername`方法返回的字段. Defaults to 'undefined'.全都返回
`encoding`: salt编码. Defaults to 'hex'.
`limitAttempts`: 是否限制登陆尝试次数. Default: false.
`maxAttempts`: 最大尝试次数. Default: Infinity.
`passwordValidator`:定义password验证方法， 'function(password,cb)'. Default: 非空验证
`usernameQueryFields`: 定义额外的用户鉴别字段 (e.g. email).
`findByUsername`: Specifies a query function that is executed with query parameters to restrict the query with extra query parameters. For example query only users with field "active" set to true. Default: function(model, queryParameters) { return model.findOne(queryParameters); }. See the examples section for a use case.
 
 6.2 config：
```
//引入前面定义好的模型，User上的authenticate()、serializeUser()、deserializeUser()方法是plm自动加上去的静态方法
const User = require('./models/user');

// > 0.2.1版本可以这样写：passport.use(User.createStrategy());
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```
6.3 plm自动加入User上的实例方法和静态方法(实例、静态的含义和mongoose一样，前者作用在实例上，后者作用在类上)：
实例方法：
> `setPassword(password, cb)`: 根据password异步生成hash和salt
`changePassword(oldPassword, newPassword, cb)`: 修改密码
`authenticate(password, cb)` : 验证
`resetAttempts(cb)`: 重置错误次数（when`options.limitAttempts=true`）

静态方法：
> `authenticate()`、`serializeUser()`、`deserializeUser()`、`createStrategy()` : 在Passport's LocalStrategy中使用
 `register(user, password, cb)`:是一个方便的注册方法，自动检查username是否为空，并自动对密码进行hash和加盐
`findByUsername()`: 方便的根据唯一用户名查找方法

# 7. 来个栗子
综上所述，我们使用express@4+passport+mongoose试验一下，首先说明，我的node版本是`8.9.3`, 对ES6语法有限支持，示例会使用ES6语法。
```
node -v
v8.9.3
```
7.1 我们不使用express-generator，自己从头建立工程，以便对整个流程更加清晰：
```
mkdir express-passport-test
cd express-passport-test
npm init
```
7.2 首先确定一下需要安装的依赖：
```
  "dependencies": {
    "body-parser": "^1.18.2",
    "cookie-parser": "^1.4.3",
    "express": "^4.16.2",
    "express-session": "^1.15.6",
    "mongoose": "^5.0.3",
    "passport": "^0.4.0",
    "passport-local": "^1.0.0",
    "passport-local-mongoose": "^4.4.0"
  }
```
 既然使用cookie和session验证，那么`body-parser`和`cookie-parser`、`express-session`自然必不可少
7.3 项目结构：
![image.png](http://upload-images.jianshu.io/upload_images/1431816-a237a9e23e832d6a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
个人有点代码洁癖，觉得官方生成的模板太乱了，就这样整理一下

7.4 *let's code*
- models/user.js(M)
```
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
```
- routes/index.js(C)
```
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
```

- utils/
   - db.js 负责数据库连接
```
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
```
   - errorHandler.js：错误处理
```
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
```
 - passport.js: passport定义及实现
```
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
```

- views:
```
//layout
doctype html
html
  head
    title= title
    meta(name='viewport', content='width=device-width, initial-scale=1.0')
    link(href='http://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css', rel='stylesheet', media='screen') 
  body
    block content
 
```
```
//index
extends layout

block content
  if (!user)
    a(href="/login") Login
    br
    a(href="/register") Register
  if (user)
    p You are currently logged in as #{user.username}
    a(href="/logout") Logout
```
```
//- login
extends layout
block content
  .container
    h1 Login Page
    p.lead Say something worthwhile here.
    br
    form(role='form', action="/login",method="post", style='max-width: 300px;')
      .form-group
          input.form-control(type='text', name="username", placeholder='Enter Username')
      .form-group
        input.form-control(type='password', name="password", placeholder='Password')
      button.btn.btn-default(type='submit') Submit
      &nbsp;
      a(href='/')
        button.btn.btn-primary(type="button") Cancel
```
```
// -register
extends layout

block content
  .container
    h1 Register Page
    p.lead Say something worthwhile here.
    br
    form(role='form', action="/register",method="post", style='max-width: 300px;')
      .form-group
          input.form-control(type='text', name="username", placeholder='Enter Username')
      .form-group
        input.form-control(type='password', name="password", placeholder='Password')
      button.btn.btn-default(type='submit') Submit
      &nbsp;
      a(href='/')
        button.btn.btn-primary(type="button") Cancel
```
```
//- error
extends layout

block content
  if (message)
    p #{message}
  if (error)
    p #{error}
    
```

最后，在appStarter.js中队所有事情进行综合：
```
/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:35:36 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 13:56:55
 * @Description: middlwareç»Ÿä¸€å½’æ”¾
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
```

然后，我得到了一个几乎什么都没有的项目启动文件：
```
/*
 * @Author: AngelaDaddy 
 * @Date: 2018-02-03 13:18:35 
 * @Last Modified by: AngelaDaddy
 * @Last Modified time: 2018-02-03 13:39:17
 * @Description: 程序入口文件
  */
const express = require('express')
const appStarter = require('./appStarter')
const app = express()
appStarter(app)
```

# 8. 启动测试：
![index](http://upload-images.jianshu.io/upload_images/1431816-cf2dd15eefd719ad.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![register](http://upload-images.jianshu.io/upload_images/1431816-6e2849b1b4d73e73.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![注册成功，自动登陆](http://upload-images.jianshu.io/upload_images/1431816-62366d05beeff1d5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![数据库](http://upload-images.jianshu.io/upload_images/1431816-5851235efcca2b71.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


至此，本教程全部完成，写的好累啊~~~手都酸了，点个赞再走呗！