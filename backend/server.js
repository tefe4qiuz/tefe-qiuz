
import express from "express";
import cors from "cors";
import admin from "firebase-admin";

const app = express();

app.use(cors({
  origin: "https://tefe4qiuz.github.io"
}));

app.use(express.json());

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

app.get("/", (req, res) => {
  res.send("TEFE QIUZ Backend is running!");
});

app.post("/verify-admin", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        authorized: false,
        message: "Authentication required"
      });
    }

    const token = authHeader.substring(7);
    const decoded = await admin.auth().verifyIdToken(token);

    if (decoded.uid !== process.env.ADMIN_UID) {
      return res.status(403).json({
        authorized: false,
        message: "Admin access denied"
      });
    }

    return res.json({
      authorized: true,
      message: "Administrator verified"
    });

  } catch (error) {
    return res.status(401).json({
      authorized: false,
      message: "Invalid login token"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`TEFE QIUZ backend running on port ${PORT}`);
});
      
