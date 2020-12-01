const DataTypes = require('sequelize');
const sequelize = require('../db/Connection');
const jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
require('dotenv/config');

const User = sequelize.define('User', {
    _id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        validate: {
            len: [0, 11]
        },
        allowNull: false
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    }
});

const Role = sequelize.define('Role', {
    _id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        validate: {
            len: [0, 11]
        },
        allowNull: false
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false
    }
});

const UserRole = sequelize.define("UserRole", {
    _id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        validate: {
            len: [0, 11]
        },
        allowNull: false
    }
});

main = async() => {

    User.belongsToMany(Role, {
        through: {
            model: UserRole,
            unique: false,
            foreignKey: 'RoleIdRole',
        }
    });

    Role.belongsToMany(User, {
        through: {
            model: UserRole,
            unique: false,
            foreignKey: 'UserIdUser',
        }
    });

    await sequelize.sync({ force: false });

    await Role.findOrCreate({
        where: { name: 'user' }
    });
    await Role.findOrCreate({
        where: { name: 'admin' }
    });
    await Role.findOrCreate({
        where: { name: 'moderator' }
    });

};

const db = {};

db.sequelize = sequelize;

db.user = User;
db.role = Role;

db.ROLES = ["user", "admin", "moderator"];

checkDuplicateEmail = async(req, res, next) => {

    await User.findOne({

            where: {
                email: req.body.email

            }
        })
        .then(user => {

            if (user) {

                res.status(400).send({ message: "Failed! Email is already in use!" });
                return;

            } else {

                next();

            }

        })
        .catch(err => {

            res.status(500).send({ message: err });
            return;

        });

};

checkRolesExisted = (req, res, next) => {
    if (req.body.role) {
        if (!db.ROLES.includes(req.body.role)) {
            res.status(400).send({
                message: `Failed! Role ${req.body.role} does not exist!`
            });
            return;
        }
    }

    next();
};

verifyToken = (req, res, next) => {
    let token = req.headers["x-access-token"];

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    jwt.verify(token, process.env.AUTH_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: "Unauthorized!" });
        }
        req.userId = decoded.id;
        next();
    });
};

isAdmin = async(req, res, next) => {
    await User.findOne({

            where: {
                _id: req.userId
            },
            include: Role
        })
        .then(user => {

            if (user) {

                if (user.dataValues.Roles.find(role => role.dataValues.name === 'admin')) {
                    next();
                    return;
                }
                res.status(403).send({ message: "Require Admin Role!" });
                return;

            }
        })
        .catch(err => {

            res.status(500).send({ message: err });
            return;

        });
};
isModerator = async(req, res, next) => {

    await User.findOne({

            where: {
                _id: req.userId
            },
            include: Role
        })
        .then(user => {

            if (user) {

                if (user.dataValues.Roles.find(role => role.dataValues.name === 'moderator')) {
                    next();
                    return;
                }
                res.status(403).send({ message: "Require Moderator Role!" });
                return;

            }
        })
        .catch(err => {

            res.status(500).send({ message: err });
            return;

        });
};

signup = async(req, res) => {

    const user = await User.create({

        username: req.body.username,
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8)

    });

    const role = await Role.findOne({
        where: {
            name: req.body.role
        }
    })

    await user.addRole(role);

    await User.findOne({
        where: { username: req.body.username },
        include: Role
    }).then(user => {

        if (user) {
            res.status(200).send({ user: user });
        }

    }).catch(err => {

        res.status(500).send({ message: err });
        return;

    });

};

signin = async(req, res) => {

    await User.findOne({
        where: { username: req.body.username },
        include: Role
    }).then(user => {

        if (user) {

            var passwordIsValid = bcrypt.compareSync(
                req.body.password,
                user.password
            );

            if (!passwordIsValid) {
                return res.status(401).send({
                    accessToken: null,
                    message: "Invalid Password!"
                });
            }

            var token = jwt.sign({ id: user._id }, process.env.AUTH_KEY, {
                expiresIn: 86400 // 24 hours
            });

            var authorities = [];

            for (let i = 0; i < user.Roles.length; i++) {
                authorities.push("ROLE_" + user.Roles[i].name.toUpperCase());
            }
            res.status(200).send({
                id: user._id,
                username: user.username,
                email: user.email,
                roles: authorities,
                accessToken: token
            });
        }

    }).catch(err => {

        res.status(500).send({ message: err });
        return;

    });

};

updateUser = async(req, res) => {};

updatePassword = async(req, res) => {};

deleteUser = async(req, res) => {};

allAccess = (req, res) => {
    res.status(200).send("Public Content.");
};

userBoard = (req, res) => {
    res.status(200).send("User Content.");
};

adminBoard = (req, res) => {
    res.status(200).send("Admin Content.");
};

moderatorBoard = (req, res) => {
    res.status(200).send("Moderator Content.");
};

module.exports = (app) => {

    main();

    app.use((req, res, next) => {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next();
    });

    app.post(
        "/api/auth/signup", [
            checkDuplicateEmail,
            checkRolesExisted
        ],
        signup
    );

    app.post("/api/auth/signin", signin);

    app.get("/api/test/all", allAccess);

    app.get("/api/test/user", [verifyToken], userBoard);

    app.get(
        "/api/test/mod", [verifyToken, isModerator],
        moderatorBoard
    );

    app.get(
        "/api/test/admin", [verifyToken, isAdmin],
        adminBoard
    );
};