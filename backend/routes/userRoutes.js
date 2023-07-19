import express from "express";
const router = express.Router();
import {
  authUser,
  registerUser,
  logoutUser,
  getUserProfile,
  updatetUserProfile,
  getUsers,
  deleteUser,
  getUsersByID,
  updateUser,
} from "../controllers/userController.js";
import { protect, admin } from "../middleware/authMiddleware.js";

router.route("/").post(registerUser).get(protect, admin, getUsers);
router.post("/logout", logoutUser);
router.post("/login", authUser);
router
  .route("/profile")
  .get(protect, getUserProfile)
  .put(protect, updatetUserProfile);
router
  .route("/:id")
  .delete(protect, admin,deleteUser)
  .get(protect, admin,getUsersByID)
  .put(protect, admin,updateUser);

export default router;
