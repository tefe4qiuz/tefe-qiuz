
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

app.post("/register-student", async (req, res) => {
  let newUser = null;

  try {
    const { fullName, email, password } = req.body;

    if (
      !fullName || !email || !password ||
      password.length < 6
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter your name, email and a password of at least 6 characters."
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanName || cleanName.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid full name."
      });
    }

    // Create Firebase Authentication account
    newUser = await admin.auth().createUser({
      email: cleanEmail,
      password: password,
      displayName: cleanName
    });

    const db = admin.firestore();

    const studentRef = db.collection("students").doc(newUser.uid);
    const counterRef = db.collection("counters").doc("studentIdCounter");

    let studentId;

    // Generate a unique ID safely using a Firestore transaction
    await db.runTransaction(async (transaction) => {
      const counter = await transaction.get(counterRef);

      const nextNumber = counter.exists
        ? counter.data().nextNumber
        : 123;

      if (
        !Number.isSafeInteger(nextNumber) ||
        nextNumber < 123
      ) {
        throw new Error("Invalid student ID counter.");
      }

      studentId = "TFQ/" + String(nextNumber).padStart(5, "0");

      transaction.set(counterRef, {
        nextNumber: nextNumber + 1
      });

      transaction.set(studentRef, {
        uid: newUser.uid,
        studentId: studentId,
        fullName: cleanName,
        email: cleanEmail,
        status: "active",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(201).json({
      success: true,
      message: "Student registration successful!",
      studentId: studentId
    });

  } catch (error) {

    // Remove the authentication account if profile creation fails
    if (newUser) {
      await admin.auth().deleteUser(newUser.uid).catch(() => {});
    }

    if (error.code === "auth/email-already-exists") {
      return res.status(409).json({
        success: false,
        message: "This email is already registered."
      });
    }

    console.error("Student registration error:", error);

    return res.status(500).json({
      success: false,
      message: "Registration failed. Please try again."
    });
  }
});


app.post("/student-login", async (req, res) => {
  try {
    const { studentId, password } = req.body;

    if (
      typeof studentId !== "string" ||
      typeof password !== "string" ||
      !studentId.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter your Student ID and password."
      });
    }

    const cleanId = studentId.trim().toUpperCase();

    const db = admin.firestore();

    // Find the student using their unique ID
    const snapshot = await db.collection("students")
      .where("studentId", "==", cleanId)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(401).json({
        success: false,
        message: "Invalid Student ID or password."
      });
    }

    const student = snapshot.docs[0].data();

    if (student.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "This student account is not active."
      });
    }

    // Verify password through Firebase Authentication
    const firebaseResponse = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" +
      process.env.FIREBASE_WEB_API_KEY,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email: student.email,
          password: password,
          returnSecureToken: true
        })
      }
    );

    const authResult = await firebaseResponse.json();
    if (!firebaseResponse.ok) {
    console.error(
        "Firebase login diagnostic:",
        authResult.error?.message || "Unknown error"
    );
    }

    if (
      !firebaseResponse.ok ||
      authResult.localId !== student.uid
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid Student ID or password."
      });
    }

    // Create a Firebase custom login token
    const customToken = await admin.auth()
      .createCustomToken(student.uid);

    return res.json({
      success: true,
      message: "Student login successful.",
      customToken: customToken,
      studentId: student.studentId,
      fullName: student.fullName
    });

  } catch (error) {
    console.error("Student login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to log in. Please try again."
    });
  }
});
      
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`TEFE QIUZ backend running on port ${PORT}`);
});
      
