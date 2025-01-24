const dotenv = require('dotenv');
dotenv.config();

const MONGO_URI = process.env.MONGO_URI;
const mongoose = require('mongoose');

mongoose.connect(MONGO_URI)
    .then(() => console.log("Connected to DB via Mongoose"))
    .catch((err) => console.log(err));

module.exports = mongoose;