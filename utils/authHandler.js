let jwt = require('jsonwebtoken')
let userController = require('../controllers/users');
let publicKey = fs.readFileSync("./keys/public.key");
module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            res.status(403).send("ban chua dang nhap");
        }
        token = token.split(" ")[1];
        try {

            // verify bằng public key
            let result = jwt.verify(token, publicKey, {
                algorithms: ["RS256"]
            });

            let user = await userController.FindById(result.id);

            if (!user) {
                return res.status(403).send("ban chua dang nhap");
            }

            req.user = user;

            next();

        } catch (error) {
            return res.status(403).send("token khong hop le");
        }
    }
};