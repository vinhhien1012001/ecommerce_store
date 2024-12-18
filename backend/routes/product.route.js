import express from "express";

const router = express.Router();

router.get("/", (req, res) => {
  res.send("Product route");
});

export default router;
