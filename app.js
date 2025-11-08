const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const sanitizeHtml = require("sanitize-html");

// POSTS STORAGE
const posts = [];
const Post = {
  getAll: () => posts,
  add: (post) => posts.push(post),
};

const app = express();

// Security headers
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "script-src": ["'self'"],
      "object-src": ["'none'"],
      "upgrade-insecure-requests": [],
    },
  })
);

// EJS setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.get("/", (req, res) => {
  const posts = Post.getAll();
  res.render("index", { posts });
});

app.get("/new", (req, res) => {
  res.render("new");
});

app.post("/new", (req, res) => {
  let { author, content } = req.body;

  const cleanAuthor = sanitizeHtml(author, { allowedTags: [], allowedAttributes: {} });
  const cleanContent = sanitizeHtml(content, {
    allowedTags: ["b", "i", "em", "strong", "a"],
    allowedAttributes: { a: ["href"] },
  });

  // Logging
  if (cleanContent !== content) {
    console.warn(
      `[XSS WARNING] Possible XSS attempt by "${author}".\nOriginal: ${content}\nSanitized: ${cleanContent}\n`
    );
  } else {
    console.log(`[INFO] Clean post submitted by ${author}`);
  }

  Post.add({ author: cleanAuthor, content: cleanContent, date: new Date().toLocaleString() });
  res.redirect("/");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
