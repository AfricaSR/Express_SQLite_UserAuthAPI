const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
require('dotenv/config');

const app = express();

var corsOptions = {
    origin: process.env.CORS
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
    res.json({ message: "Hello World!" });
});

const PORT = process.env.PORT;

require('./services/UserService')(app);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});
