import crypto from "crypto";
export const generateToken = () => {
    return crypto.randomBytes(16).toString("hex");
};
//# sourceMappingURL=emai.utils.js.map