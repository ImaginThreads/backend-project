const express = require("express");
const app = express();
const userModel = require("./models/user");
const postModel = require("./models/post");
const cookieParser = require('cookie-parser');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const post = require("./models/post");
const crypto = require("crypto");
const path = require("path");
const multerconfig = require("./config/multerconfig");
const upload = multerconfig.upload; 




app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());



  
 

app.get('/', (req, res) => {
    res.render("index")
});

app.get('/profile/upload', (req, res) => {
    res.render("profileupload")
});
app.post('/upload', isLoggedIn ,upload.single("image"), async (req, res) => {
 let user = await userModel.findOne({email: req.user.email});
 user.profilepic = req.file.filename;
 await user.save();
 res.redirect("/profile")
});


app.get('/login', (req, res) => {
    res.render("login")
});

app.get('/profile', isLoggedIn, async (req, res) => {
    try {
        let user = await userModel.findOne({ email: req.user.email }).populate("posts");
        if (!user) {
            return res.status(404).send("User not found");
        }
        res.render("profile", { user });
    } catch (err) {
        console.error(err);
        res.status(500).send("An error occurred while fetching the user profile.");
    }
});


app.get('/like/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({_id: req.params.id}).populate("user");
    if (post.likes.indexOf(req.user.userid) === -1) {
        post.likes.push(req.user.userid);
    } else {
        post.likes.splice(post.likes.indexOf(req.user.userid), 1);
    }
    await post.save();
    res.redirect("/profile");
});

app.get('/edit/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({_id: req.params.id}).populate("user");

    res.render("edit", {post});
});



app.post('/update/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOneAndUpdate({_id: req.params.id}, {content: req.body.content});

    res.redirect("/profile")
});

app.post('/post', isLoggedIn , async (req, res) => {
    let user = await userModel.findOne({email: req.user.email});
    let {content} = req.body;
    if (!user) {
        return res.status(404).send("User not found");
    }

    if (!user.posts) {
        user.posts = [];  
    }
let post = await postModel.create({
    user: user._id,
    content
});
user.posts.push(post._id);
await user.save();
res.redirect("/profile");

});

app.post('/register', async (req, res) => {
    let { email, username, name, password, age } = req.body;

    let user = await userModel.findOne({ email });
    if (user) return res.status(500).send("User already exists");

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.status(500).send("Error generating salt");
        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.status(500).send("Error hashing password");

            try {
                let newUser = await userModel.create({
                    username,
                    email,
                    name,
                    age,
                    password: hash
                });

                let token = jwt.sign({ email: email, userid: newUser._id }, "shhhh");
                res.cookie("token", token);
                res.redirect("/profile"); // Corrected from res.render("/profile")
            } catch (err) {
                res.status(500).send("Error creating user");
            }
        });
    });
});

app.post('/login', async (req, res) => {
    let { email, password } = req.body;

    let user = await userModel.findOne({ email });
    if (!user) return res.status(500).send("Something went wrong");

    bcrypt.compare(password, user.password, (err, result) => {
        if (err) return res.status(500).send("Error comparing passwords");

        if (result) {
            let token = jwt.sign({ email: email, userid: user._id }, "shhhh"); // Use user._id
            res.cookie("token", token);
            res.status(200).redirect("/profile");
        } else {
            res.redirect("/login");
        }
    });
});


app.get('/logout', (req, res) => {
    res.cookie("token", "");
    res.redirect("/login")
});
function isLoggedIn(req, res, next) {
    if (!req.cookies.token) {
        // Redirect to login if no token is present
        return res.redirect("/login");
    }

    try {
        // Verify the token
        let data = jwt.verify(req.cookies.token, "shhhh");
        req.user = data; // Attach user data to request object
        next(); // Call the next middleware/route handler
    } catch (err) {
        // If token verification fails, redirect to login
        return res.redirect("/login");
    }
}

app.listen(3000);
