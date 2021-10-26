/*~~-_=_= Variables =_=_-~~~*/

require('dotenv').config()
var session = require('express-session');
var MongoDBStore = require('connect-mongodb-session')(session);
const express = require('express');
var crypto = require('crypto');
function toLowerCase(txt) {
    return txt.toLowerCase();
}
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const { readSync } = require('fs');
const passport = require('passport');
function createHash(text) {
    const hash = crypto.createHash('sha256');
    return hash.update(text).digest("hex")
}

/*~~-_=_= Middleware =_=_-~~~*/

app.set('view engine', 'ejs');
mongoose.connect(`mongodb+srv://${process.env.DBUSERNAME}:${process.env.DBPASSWORD}@cluster0.ej84v.mongodb.net/loginWebsite?retryWrites=true&w=majority`)
var store = new MongoDBStore({
    uri: `mongodb+srv://${process.env.DBUSERNAME}:${process.env.DBPASSWORD}@cluster0.ej84v.mongodb.net/sessions?retryWrites=true&w=majority`,
    collection: 'mySessions'
});
store.on('error', function (error) {
    console.log(error);
});
app.use(require('express-session')({
    secret: process.env.SESSIONID,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
    },

    store: store,
    // Boilerplate options, see:
    // * https://www.npmjs.com/package/express-session#resave
    // * https://www.npmjs.com/package/express-session#saveuninitialized
    resave: true,
    saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

app.use('/static', express.static(require('path').join(__dirname, 'static')))
/*~~-_=_= Models and Schemas =_=_-~~~*/

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    rank: Number,
    warned: Boolean,
    warn: Array
})

const User = mongoose.model('users', userSchema)
const postSchema = new mongoose.Schema({
    title: String,
    body: String,
    author: String,
    postid: String,
    deleted: Boolean
})
const Post = mongoose.model('posts', postSchema)
const reportSchema = new mongoose.Schema({
    title: String,
    body: String,
    author: String,
    postid: String,
    deleted: Boolean,
    postauthor: String
})
const Report = mongoose.model('reports', reportSchema)
/*~~-_=_= Routes =_=_-~~~*/

app.get("/", async (req, res) => {

    if (req.session.user) {
        const user = await User.find({ username: req.session.user })
        if(user[0].warned == true){
            res.redirect('/warn')
            return
        }
        if (!user[0]) {
            res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
            return
        }
        if (user[0].rank == 0) {

            res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
            return
        }
        res.render(__dirname + "/ejs/index.ejs", { user: req.session.user })
    }
    else {
        res.render(__dirname + "/ejs/index.ejs")
    }

})
app.get('/post/report', async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }

    res.render(__dirname + "/ejs/reportpost.ejs")
})
app.post('/post/report', async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    const title = req.body.title
    const id = req.body.id
    const body = req.body.body
    if (!body || !title) {
        res.redirect("/app")
        return
    }
    const ifExist = await Post.find({ postid: id })
    if (!ifExist[0]) {
        res.redirect("/post/report")
        return
    }
    const newPost = new Report({
        title: title,
        body: body,
        author: req.session.user,
        deleted: false,
        postid: id,
        postauthor: ifExist[0].author
    })
    await newPost.save()

    res.redirect("/app")
})
app.get("/reports", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank < 2) {

        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }


    const posts = await Report.find({ deleted: false })
    posts.reverse()
    res.render(__dirname + "/ejs/reports.ejs", { user: req.session.user, posts: posts })
})
app.get("/signup", (req, res) => {
    if (req.session.user) {

        res.redirect("/")
        return
    }
    res.render(__dirname + "/ejs/signup.ejs")
})
app.post("/signup", async (req, res) => {
    if (!req.body.username || !req.body.password) {
        res.redirect("/")
        return
    }
    const users = await User.find({ username: toLowerCase(req.body.username) })
    
    if (users[0]) {
        res.render(__dirname + "/ejs/signup.ejs", { msg: "User already exists." })
        return
    }
    const newUser = new User({
        username: toLowerCase(req.body.username),
        password: createHash(req.body.password),
        rank: 1
    })
    await newUser.save()
    res.render(__dirname + "/ejs/login.ejs", { msg: "User saved successfully. Please login :)" })
})
app.get("/login", (req, res) => {
    if (req.session.user) {
        res.redirect("/")
        return
    }
    
    res.render(__dirname + "/ejs/login.ejs")
    
})
app.post("/login", async (req, res) => {
    if (!req.body.username || !req.body.password) {
        res.redirect("/")
        return
    }

    const users = await User.find({ username: toLowerCase(req.body.username), password: createHash(req.body.password) })
    
    if (users[0]) {
        req.session.user = toLowerCase(req.body.username)
        res.redirect("/")
    }
    else {
        res.render(__dirname + '/ejs/login.ejs', { msg: "Username or password is incorrect." })
    }
})
app.get("/logout", (req, res) => {
    req.session.destroy()
    res.redirect("/")
})
app.post("/reports/resolve", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank < 2) {

        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    const msg = await Report.find({ postid: req.body.postid, deleted: false })
    if (!msg[0]) {
        res.redirect("/reports")
        return
    }

    msg[0].deleted = true
    await msg[0].save()
    res.redirect("/reports")
})
app.post("/reports/delete", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (user[0].rank < 2) {

        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    const msg = await Post.find({ postid: req.body.postid, deleted: false })
    if (!msg[0]) {
        res.redirect("/reports")
        return
    }

    msg[0].deleted = true
    await msg[0].save()
    res.redirect("/reports")
})
app.post("/reports/blacklist", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return

    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank < 2) {

        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    const msg = await Post.find({ postid: req.body.postid, deleted: false })
    if (!msg[0]) {
        res.redirect("/reports")
        return
    }

    const newUser = await User.find({ username: msg[0].author })


    if (!newUser[0]) {
        res.redirect("/reports")
        return
    }

    newUser[0].rank = 0
    await newUser[0].save()
    res.redirect("/reports")
})
app.post("/reports/warn", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (user[0].rank < 2) {

        res.status(403).render(__dirname + "/ejs/404.ejs", { code: "403 - Forbidden" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    const msg = await Post.find({ postid: req.body.postid })
    if (!msg[0]) {
        res.redirect("/reports")
        return
    }
    console.dir(msg[0])
    const newUser = await User.find({ username: msg[0].author })
    if (!newUser[0]) {
        res.redirect("/reports")
        return
    }
    const newMsg = {
        title: msg[0].title,
        body: msg[0].body,
        author: msg[0].author,
        postid: msg[0].postid
    }
    const warn = newUser[0].warn
    
    warn.push(newMsg)
    newUser[0].warned = true
    newUser[0].warn = warn
    
    await newUser[0].save()
    res.redirect("/reports")
})
app.get('/rules', async (req, res) => {
    res.render(__dirname + "/ejs/rules.ejs")
})
app.get("/warn", async (req, res) => {
    const user = await User.find({ username: req.session.user })

    if(!user[0]) {
        res.redirect('/')
        return
    }
    if(typeof user[0].warned === undefined){
        res.redirect('/')
        return
    }
    if(user[0].warned !== true){
        res.redirect('/')
        return
    }

    res.render(__dirname + '/ejs/warn.ejs', {posts: user[0].warn })
})
app.post('/warn', async (req, res) => {
    const user = await User.find({ username: req.session.user })

    if(!user[0]) {
        res.redirect('/')
        return
    }
    
    if(typeof user[0].warned === undefined){
        res.redirect('/')
        return
    }
    if(user[0].warned !== true){
        res.redirect('/')
        return
    }
    user[0].warn = []
    user[0].warned = false
    await user[0].save()

    res.redirect('/')
})
app.get("/admin", async (req, res) => {

    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (req.session.user) {
        res.render(__dirname + "/ejs/admin.ejs", { rank: user[0].rank })
    } else {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
    }
})

app.get("/password-reset", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (req.session.user) {
        res.render(__dirname + "/ejs/password-reset.ejs", { user: req.session.user })
    } else {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
    }

})

app.post("/password-reset", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (!req.body.currentpassword || !req.body.newpassword || !req.body.confirmpassword) {
        res.redirect("/")
        return
    }
    if (req.body.newpassword !== req.body.confirmpassword) {
        res.render(__dirname + "/ejs/password-reset.ejs", { msg: "Passwords do not match.", user: req.session.user })
        return
    }
    const users = await User.find({ username: req.session.user })
    if (!users[0]) {
        res.redirect("/")
        return
    }

    if (createHash(req.body.currentpassword) !== users[0].password) {
        res.render(__dirname + "/ejs/password-reset.ejs", { msg: "Your current password is incorrect.", user: req.session.user })
        return
    }

    users[0].password = createHash(req.body.confirmpassword)
    await users[0].save()

    req.session.destroy()

    res.render(__dirname + "/ejs/login.ejs", { msg: "You have successfully changed your password. Please login again." })
})

app.get("/app", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (!req.session.user) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    const posts = await Post.find({ deleted: false })
    posts.reverse()
    res.render(__dirname + "/ejs/posts.ejs", { user: req.session.user, posts: posts })
})
app.get("/post/create", async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if (!req.session.user) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    res.render(__dirname + "/ejs/createpost.ejs")
})
app.post('/post/create', async (req, res) => {
    const user = await User.find({ username: req.session.user })
    if (!user[0]) {
        res.render(__dirname + "/ejs/404.ejs", { code: "401 - Unauthorized" })
        return
    }
    if (user[0].rank == 0) {

        res.status(403.8).send("403.8 - Site access denied <br> <br> <br> <h1>You have been blacklisted.</h1>")
        return
    }
    if(user[0].warned == true){
        res.redirect('/warn')
        return
    }
    const title = req.body.title
    const body = req.body.body
    if (!body || !title) {
        res.redirect("/app")
        return
    }
    const posts = await Post.find()
    const newestPost = await posts[posts.length - 1]

    const newId = parseInt(newestPost.postid) + 1
    const newPost = new Post({
        title: title,
        body: body,
        author: req.session.user,
        deleted: false,
        postid: newId + ""
    })
    await newPost.save()

    res.redirect("/app")
})

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google"
  },
  function(accessToken, refreshToken, profile, done) {
    
  }
));

app.get('/social/google',
  passport.authenticate('google', { scope: ['profile'] }));


  app.get('/auth/google/', 
  passport.authenticate('google', { failureRedirect: '/login' }), function (req, res){
    console.dir(req)
  })
// ALWAYS LAST

app.use(function (err, req, res, next) {
    console.error(err)


    var today = new Date();
    var date = today.getFullYear() + '-' + (today.getMonth() + 1) + '-' + today.getDate();
    var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
    var dateTime = date + ' ' + time;
    console.warn("^^^^^^^^ " + dateTime)
    res.status(500).send(`Something broke! Please send an <a href = "mailto:spacebugreport@gmail.com?subject = Bug Report&body = ${btoa(dateTime)}">email</a> to us! <br> <b>PLEASE INCLUDE THE FOLLOWING ERROR CODE: <code>${btoa(dateTime)}</code></b>`)
})

app.use(function (req, res) {
    res.status(404).render(__dirname + '/ejs/404.ejs', { code: "404 - Page not found" });
});


app.listen(8080, (err) => {
    if (err) { return console.error(err) }
    console.log("Listening on port 8080")
})