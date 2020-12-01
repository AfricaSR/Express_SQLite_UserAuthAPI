const { Sequelize } = require('sequelize');
Sequelize.Promise = global.Promise;
require('dotenv/config');

module.exports = new Sequelize({
    dialect: 'sqlite',
    storage: process.env.DB,
    logging: false
});