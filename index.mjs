// index.mjs
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    "❌ Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env file"
  );
  process.exit(1);
}

// Supabase client (ใช้ service role key ฝั่ง backend เท่านั้น)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Authentication APIs
 *   - name: Public
 *     description: Public portfolio APIs
 *   - name: Me
 *     description: Current user's portfolio APIs
 *   - name: Experiences
 *     description: CRUD experiences of current user
 *   - name: Projects
 *     description: CRUD projects of current user
 */

// ----------------------
// Helpers
// ----------------------

async function getOrCreateProfileByUserId(userId) {
  // หาว่ามี profile ของ user นี้หรือยัง
  let { data: profile, error: pErr } = await supabase
    .from("profiles")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (pErr) {
    console.error("Profile select error:", pErr.message);
    throw new Error(pErr.message);
  }

  // ถ้ายังไม่มี profile ให้สร้างใหม่
  if (!profile) {
    const { data: inserted, error: insErr } = await supabase
      .from("profiles")
      .insert({
        user_id: userId,
        first_name: "",
        last_name: "",
        about: "",
      })
      .select("*")
      .maybeSingle();

    if (insErr) {
      console.error("Profile insert error:", insErr.message);
      throw new Error(insErr.message);
    }
    profile = inserted;
  }

  return profile;
}

// Auth middleware
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

  const token = authHeader.split(" ")[1];

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data || !data.user) {
    console.error("Auth error:", error ? error.message : "no user");
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  req.user = data.user; // { id, email, ... }
  req.token = token;
  next();
}

// ----------------------
// Auth endpoints
// ----------------------
/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register new user with email & password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Invalid input or email already used
 *       500:
 *         description: Internal server error
 */
// POST /api/auth/register
// body: { email, password }
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      console.error("SignUp error:", error.message);
      return res.status(400).json({ error: error.message });
    }

    const user = data.user;
    let session = data.session;

    // ถ้าเปิด email confirmation อาจไม่มี session ให้ login ให้เลย
    if (!session) {
      const { data: loginData, error: loginError } =
        await supabase.auth.signInWithPassword({ email, password });

      if (loginError) {
        console.error("Auto-login after signUp error:", loginError.message);
        return res.status(200).json({
          token: null,
          user: {
            id: user.id,
            email: user.email,
          },
          message:
            "User registered. Please verify email (if confirmation is enabled).",
        });
      }

      session = loginData.session;
    }

    const token = session ? session.access_token : null;
    if (!token || !user) {
      return res.status(500).json({
        error: "User created but no session token. Check Supabase auth config.",
      });
    }

    // สร้าง profile ให้ user ถ้ายังไม่มี
    try {
      await getOrCreateProfileByUserId(user.id);
    } catch (e) {
      // ไม่ถึงกับ fail ทั้ง register แต่ log ไว้
      console.error("Create profile after signUp error:", e.message);
    }

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Unexpected register error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/login
/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login with email & password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login success
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       401:
 *         description: Invalid email or password
 *       500:
 *         description: Internal server error
 */
// body: { email, password }
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      console.error("Login error:", error.message);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = data.user;
    const session = data.session;
    const token = session ? session.access_token : null;

    if (!user || !token) {
      return res
        .status(500)
        .json({ error: "Login succeeded but no token returned" });
    }

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Unexpected login error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout current user (stateless)
 *     description: >
 *       For stateless JWT: backend just returns success, frontend should forget the token.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout success
 *       401:
 *         description: Unauthorized
 */
// POST /api/auth/logout
app.post("/api/auth/logout", requireAuth, (req, res) => {
  // ใช้ token-based stateless -> แค่ให้ frontend ลบ token ก็พอ
  return res.json({ success: true });
});

// ----------------------
// Public portfolios
// ----------------------
/**
 * @swagger
 * /api/public/portfolios:
 *   get:
 *     summary: Get featured and all public portfolios
 *     tags: [Public]
 *     responses:
 *       200:
 *         description: List of public portfolios
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PublicPortfoliosResponse'
 *       500:
 *         description: Internal server error
 */

// GET /api/public/portfolios
// -> { featured: [...], list: [...] }
app.get("/api/public/portfolios", async (req, res) => {
  try {
    const { data: featuredData, error: fErr } = await supabase
      .from("profiles")
      .select(
        "id, user_id, first_name, last_name, about, avatar_url, is_featured"
      )
      .eq("is_featured", true)
      .order("updated_at", { ascending: false })
      .limit(5);

    if (fErr) {
      console.error("Featured error:", fErr.message);
      return res.status(500).json({ error: fErr.message });
    }

    const { data: allData, error: aErr } = await supabase
      .from("profiles")
      .select(
        "id, user_id, first_name, last_name, about, avatar_url, is_featured"
      )
      .order("updated_at", { ascending: false });

    if (aErr) {
      console.error("All profiles error:", aErr.message);
      return res.status(500).json({ error: aErr.message });
    }

    const featured = featuredData || [];
    const all = allData || [];

    return res.json({
      featured,
      list: all,
    });
  } catch (err) {
    console.error("Unexpected public portfolios error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ----------------------
// Me / Portfolio (รวมทั้งหมดทีเดียว)
// ----------------------
/**
 * @swagger
 * /api/me/portfolio:
 *   get:
 *     summary: Get current user's portfolio (profile + experiences + projects)
 *     tags: [Me]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Portfolio data of current user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MyPortfolio'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */

// GET /api/me/portfolio
// -> { profile, experiences, projects }
app.get("/api/me/portfolio", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;

    // experiences
    const { data: experiencesData, error: eErr } = await supabase
      .from("experiences")
      .select("*")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (eErr) {
      console.error("Experiences error:", eErr.message);
      return res.status(500).json({ error: eErr.message });
    }

    // projects
    const { data: projectsData, error: prErr } = await supabase
      .from("projects")
      .select("id, profile_id, title, subtitle, cover_image_url, order_index")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (prErr) {
      console.error("Projects error:", prErr.message);
      return res.status(500).json({ error: prErr.message });
    }

    let projects = projectsData || [];
    if (projects.length > 0) {
      const projectIds = projects.map((p) => p.id);
      const { data: partsData, error: partsErr } = await supabase
        .from("project_parts")
        .select("*")
        .in("project_id", projectIds)
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Project parts error:", partsErr.message);
        return res.status(500).json({ error: partsErr.message });
      }

      const parts = partsData || [];
      const partsByProject = {};
      for (const part of parts) {
        if (!partsByProject[part.project_id]) {
          partsByProject[part.project_id] = [];
        }
        partsByProject[part.project_id].push(part);
      }

      projects = projects.map((p) => ({
        ...p,
        parts: partsByProject[p.id] || [],
      }));
    }

    return res.json({
      profile,
      experiences: experiencesData || [],
      projects,
    });
  } catch (err) {
    console.error("Unexpected me/portfolio error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * @swagger
 * /api/public/portfolios/{id}:
 *   get:
 *     summary: Get public portfolio detail by profile id
 *     description: >
 *       Returns profile, experiences, and projects (with parts) for a given profile id.
 *       This endpoint is public and does not require authentication.
 *     tags: [Public]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           description: Profile ID (UUID)
 *     responses:
 *       200:
 *         description: Public portfolio detail
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MyPortfolio'
 *       404:
 *         description: Profile not found
 *       500:
 *         description: Internal server error
 */

app.get("/api/public/portfolios/:id", async (req, res) => {
  try {
    const profileId = req.params.id;

    // 1) ดึง profile ตาม id (ไม่ auto-create)
    const { data: profile, error: pErr } = await supabase
      .from("profiles")
      .select(
        "id, user_id, first_name, last_name, about, avatar_url, is_featured, updated_at"
      )
      .eq("id", profileId)
      .maybeSingle();

    if (pErr) {
      console.error("Public portfolio profile error:", pErr.message);
      return res.status(500).json({ error: pErr.message });
    }

    if (!profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    // 2) experiences ของ profile นี้
    const { data: experiences, error: eErr } = await supabase
      .from("experiences")
      .select("*")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (eErr) {
      console.error("Public portfolio experiences error:", eErr.message);
      return res.status(500).json({ error: eErr.message });
    }

    // 3) projects + parts ของ profile นี้
    const { data: projectsData, error: prErr } = await supabase
      .from("projects")
      .select("id, profile_id, title, subtitle, cover_image_url, order_index")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (prErr) {
      console.error("Public portfolio projects error:", prErr.message);
      return res.status(500).json({ error: prErr.message });
    }

    let projects = projectsData || [];
    if (projects.length > 0) {
      const projectIds = projects.map((p) => p.id);

      const { data: partsData, error: partsErr } = await supabase
        .from("project_parts")
        .select("*")
        .in("project_id", projectIds)
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Public portfolio parts error:", partsErr.message);
        return res.status(500).json({ error: partsErr.message });
      }

      const parts = partsData || [];
      const partsByProject = {};
      for (const part of parts) {
        if (!partsByProject[part.project_id]) {
          partsByProject[part.project_id] = [];
        }
        partsByProject[part.project_id].push(part);
      }

      projects = projects.map((p) => ({
        ...p,
        parts: partsByProject[p.id] || [],
      }));
    }

    return res.json({
      profile,
      experiences: experiences || [],
      projects,
    });
  } catch (err) {
    console.error("Unexpected public portfolio detail error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /api/me/profile
/**
 * @swagger
 * /api/me/profile:
 *   put:
 *     summary: Update current user's profile
 *     tags: [Me]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               about:
 *                 type: string
 *               avatar_url:
 *                 type: string
 *               is_featured:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Updated profile
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Profile'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
// body: { first_name, last_name, about, avatar_url, is_featured }
app.put("/api/me/profile", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { first_name, last_name, about, avatar_url, is_featured } = req.body;

    const { data, error } = await supabase
      .from("profiles")
      .update({
        first_name,
        last_name,
        about,
        avatar_url,
        is_featured,
        updated_at: new Date().toISOString(),
      })
      .eq("user_id", userId)
      .select("*")
      .maybeSingle();

    if (error) {
      console.error("Update profile error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json(data);
  } catch (err) {
    console.error("Unexpected update profile error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ----------------------
// CRUD: Experiences (ของ user ปัจจุบัน)
// ----------------------
/**
 * @swagger
 * /api/me/experiences:
 *   get:
 *     summary: Get all experiences of current user
 *     tags: [Experiences]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of experiences
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Experience'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */


// GET /api/me/experiences
app.get("/api/me/experiences", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;

    const { data, error } = await supabase
      .from("experiences")
      .select("*")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (error) {
      console.error("Get experiences error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json(data || []);
  } catch (err) {
    console.error("Unexpected get experiences error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/me/experiences
/**
 * @swagger
 * /api/me/experiences:
 *   post:
 *     summary: Create new experience for current user
 *     tags: [Experiences]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [company, position]
 *             properties:
 *               company:
 *                 type: string
 *               position:
 *                 type: string
 *               start_date:
 *                 type: string
 *                 format: date
 *               end_date:
 *                 type: string
 *                 format: date
 *               description:
 *                 type: string
 *               order_index:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Experience created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Experience'
 *       400:
 *         description: Missing required fields
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
// body: { company, position, start_date, end_date, description, order_index? }
app.post("/api/me/experiences", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;

    const {
      company,
      position,
      start_date,
      end_date,
      description,
      order_index,
    } = req.body;

    if (!company || !position) {
      return res
        .status(400)
        .json({ error: "company and position are required" });
    }

    // หา order_index ถ้าไม่ได้ส่งมา
    let finalOrderIndex = 1;
    if (typeof order_index === "number") {
      finalOrderIndex = order_index;
    } else {
      const { data: lastExp, error: lastErr } = await supabase
        .from("experiences")
        .select("order_index")
        .eq("profile_id", profileId)
        .order("order_index", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (lastErr) {
        console.error("Get last experience error:", lastErr.message);
      }
      if (lastExp && typeof lastExp.order_index === "number") {
        finalOrderIndex = lastExp.order_index + 1;
      }
    }

    const { data, error } = await supabase
      .from("experiences")
      .insert({
        profile_id: profileId,
        company,
        position,
        start_date,
        end_date,
        description,
        order_index: finalOrderIndex,
      })
      .select("*")
      .maybeSingle();

    if (error) {
      console.error("Insert experience error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.status(201).json(data);
  } catch (err) {
    console.error("Unexpected create experience error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /api/me/experiences/:id
/**
 * @swagger
 * /api/me/experiences/{id}:
 *   put:
 *     summary: Update an experience of current user
 *     tags: [Experiences]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Experience ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               company:
 *                 type: string
 *               position:
 *                 type: string
 *               start_date:
 *                 type: string
 *                 format: date
 *               end_date:
 *                 type: string
 *                 format: date
 *               description:
 *                 type: string
 *               order_index:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Updated experience
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Experience'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Experience not found
 *       500:
 *         description: Internal server error
 */
app.put("/api/me/experiences/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;
    const id = parseInt(req.params.id, 10);

    const {
      company,
      position,
      start_date,
      end_date,
      description,
      order_index,
    } = req.body;

    const updateData = {
      company,
      position,
      start_date,
      end_date,
      description,
      order_index,
    };

    // ลบ field ที่เป็น undefined ออก
    Object.keys(updateData).forEach((key) => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    const { data, error } = await supabase
      .from("experiences")
      .update(updateData)
      .eq("id", id)
      .eq("profile_id", profileId)
      .select("*")
      .maybeSingle();

    if (error) {
      console.error("Update experience error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    if (!data) {
      return res.status(404).json({ error: "Experience not found" });
    }

    return res.json(data);
  } catch (err) {
    console.error("Unexpected update experience error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api/me/experiences/:id
/**
 * @swagger
 * /api/me/experiences/{id}:
 *   delete:
 *     summary: Delete an experience of current user
 *     tags: [Experiences]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Experience ID
 *     responses:
 *       200:
 *         description: Deleted successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.delete("/api/me/experiences/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;
    const id = parseInt(req.params.id, 10);

    const { error } = await supabase
      .from("experiences")
      .delete()
      .eq("id", id)
      .eq("profile_id", profileId);

    if (error) {
      console.error("Delete experience error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Unexpected delete experience error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ----------------------
// CRUD: Projects (ของ user ปัจจุบัน) + Parts
// ----------------------
/**
 * @swagger
 * /api/me/projects:
 *   get:
 *     summary: Get all projects of current user (with parts)
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of projects with parts
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/ProjectWithParts'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
// GET /api/me/projects
app.get("/api/me/projects", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;

    const { data: projectsData, error: pErr } = await supabase
      .from("projects")
      .select("id, profile_id, title, subtitle, cover_image_url, order_index")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (pErr) {
      console.error("Get projects error:", pErr.message);
      return res.status(500).json({ error: pErr.message });
    }

    let projects = projectsData || [];
    if (projects.length > 0) {
      const projectIds = projects.map((p) => p.id);
      const { data: partsData, error: partsErr } = await supabase
        .from("project_parts")
        .select("*")
        .in("project_id", projectIds)
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Get project parts error:", partsErr.message);
        return res.status(500).json({ error: partsErr.message });
      }

      const parts = partsData || [];
      const partsByProject = {};
      for (const part of parts) {
        if (!partsByProject[part.project_id]) {
          partsByProject[part.project_id] = [];
        }
        partsByProject[part.project_id].push(part);
      }

      projects = projects.map((p) => ({
        ...p,
        parts: partsByProject[p.id] || [],
      }));
    }

    return res.json(projects);
  } catch (err) {
    console.error("Unexpected get projects error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/me/projects
/**
 * @swagger
 * /api/me/projects:
 *   post:
 *     summary: Create new project for current user
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title]
 *             properties:
 *               title:
 *                 type: string
 *               subtitle:
 *                 type: string
 *               cover_image_url:
 *                 type: string
 *               order_index:
 *                 type: integer
 *               parts:
 *                 type: array
 *                 items:
 *                   $ref: '#/components/schemas/ProjectPart'
 *     responses:
 *       201:
 *         description: Project created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ProjectWithParts'
 *       400:
 *         description: Missing required fields
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
// body: { title, subtitle?, cover_image_url?, order_index?, parts?: [ {...} ] }
app.post("/api/me/projects", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;

    const {
      title,
      subtitle,
      cover_image_url,
      order_index,
      parts: partsInput,
    } = req.body;

    if (!title) {
      return res.status(400).json({ error: "title is required" });
    }

    // หา order_index ถ้าไม่ได้ส่งมา
    let finalOrderIndex = 1;
    if (typeof order_index === "number") {
      finalOrderIndex = order_index;
    } else {
      const { data: lastProj, error: lastErr } = await supabase
        .from("projects")
        .select("order_index")
        .eq("profile_id", profileId)
        .order("order_index", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (lastErr) {
        console.error("Get last project error:", lastErr.message);
      }
      if (lastProj && typeof lastProj.order_index === "number") {
        finalOrderIndex = lastProj.order_index + 1;
      }
    }

    // สร้าง project
    const { data: project, error: projErr } = await supabase
      .from("projects")
      .insert({
        profile_id: profileId,
        title,
        subtitle,
        cover_image_url,
        order_index: finalOrderIndex,
      })
      .select("*")
      .maybeSingle();

    if (projErr) {
      console.error("Insert project error:", projErr.message);
      return res.status(500).json({ error: projErr.message });
    }

    let parts = [];
    if (Array.isArray(partsInput) && partsInput.length > 0) {
      const rowsToInsert = partsInput.map((p, idx) => ({
        project_id: project.id,
        title: p.title || null,
        content: p.content || null,
        image_url: p.image_url || null,
        link_url: p.link_url || null,
        kind: p.kind || null,
        order_index:
          typeof p.order_index === "number" ? p.order_index : idx + 1,
      }));

      const { data: insertedParts, error: partsErr } = await supabase
        .from("project_parts")
        .insert(rowsToInsert)
        .select("*")
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Insert project parts error:", partsErr.message);
        // ไม่ fail ทั้ง project แต่ log ไว้
      } else {
        parts = insertedParts || [];
      }
    }

    return res.status(201).json({ ...project, parts });
  } catch (err) {
    console.error("Unexpected create project error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /api/me/projects/:id
/**
 * @swagger
 * /api/me/projects/{id}:
 *   put:
 *     summary: Update a project (and optionally its parts)
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               subtitle:
 *                 type: string
 *               cover_image_url:
 *                 type: string
 *               order_index:
 *                 type: integer
 *               parts:
 *                 type: array
 *                 description: If provided, will replace all existing parts.
 *                 items:
 *                   $ref: '#/components/schemas/ProjectPart'
 *     responses:
 *       200:
 *         description: Updated project with parts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ProjectWithParts'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Project not found
 *       500:
 *         description: Internal server error
 */

// body: { title?, subtitle?, cover_image_url?, order_index?, parts?: [ {...} ] }
// parts จะใช้วิธีง่าย ๆ คือ ลบของเดิมทั้งหมดแล้ว insert ใหม่
app.put("/api/me/projects/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;
    const projectId = parseInt(req.params.id, 10);

    const {
      title,
      subtitle,
      cover_image_url,
      order_index,
      parts: partsInput,
    } = req.body;

    const updateData = {
      title,
      subtitle,
      cover_image_url,
      order_index,
    };

    Object.keys(updateData).forEach((key) => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    const { data: project, error: projErr } = await supabase
      .from("projects")
      .update(updateData)
      .eq("id", projectId)
      .eq("profile_id", profileId)
      .select("*")
      .maybeSingle();

    if (projErr) {
      console.error("Update project error:", projErr.message);
      return res.status(500).json({ error: projErr.message });
    }

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    let parts = [];
    if (Array.isArray(partsInput)) {
      // ลบ parts เดิมทั้งหมด
      const { error: delErr } = await supabase
        .from("project_parts")
        .delete()
        .eq("project_id", projectId);

      if (delErr) {
        console.error("Delete old project parts error:", delErr.message);
      }

      if (partsInput.length > 0) {
        const rowsToInsert = partsInput.map((p, idx) => ({
          project_id: projectId,
          title: p.title || null,
          content: p.content || null,
          image_url: p.image_url || null,
          link_url: p.link_url || null,
          kind: p.kind || null,
          order_index:
            typeof p.order_index === "number" ? p.order_index : idx + 1,
        }));

        const { data: insertedParts, error: partsErr } = await supabase
          .from("project_parts")
          .insert(rowsToInsert)
          .select("*")
          .order("order_index", { ascending: true });

        if (partsErr) {
          console.error("Insert new project parts error:", partsErr.message);
        } else {
          parts = insertedParts || [];
        }
      }
    } else {
      // ถ้าไม่ได้ส่ง parts มา ก็โหลด parts เดิมกลับไปให้
      const { data: existingParts, error: partsErr } = await supabase
        .from("project_parts")
        .select("*")
        .eq("project_id", projectId)
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Load existing project parts error:", partsErr.message);
      } else {
        parts = existingParts || [];
      }
    }

    return res.json({ ...project, parts });
  } catch (err) {
    console.error("Unexpected update project error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api/me/projects/:id
/**
 * @swagger
 * /api/me/projects/{id}:
 *   delete:
 *     summary: Delete a project and its parts
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Deleted successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.delete("/api/me/projects/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const profile = await getOrCreateProfileByUserId(userId);
    const profileId = profile.id;
    const projectId = parseInt(req.params.id, 10);

    // ลบ parts ก่อน
    const { error: partsErr } = await supabase
      .from("project_parts")
      .delete()
      .eq("project_id", projectId);

    if (partsErr) {
      console.error("Delete project parts error:", partsErr.message);
    }

    // ลบ project
    const { error: projErr } = await supabase
      .from("projects")
      .delete()
      .eq("id", projectId)
      .eq("profile_id", profileId);

    if (projErr) {
      console.error("Delete project error:", projErr.message);
      return res.status(500).json({ error: projErr.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Unexpected delete project error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * @swagger
 * /api/auth/reset-password-request:
 *   post:
 *     summary: Request password reset via email
 *     description: >
 *       Sends a reset link to the email if it exists.
 *       Response is the same regardless of whether the email exists (for security).
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Reset request accepted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       500:
 *         description: Internal server error
 */
// POST /api/auth/reset-password-request
// body: { email }
app.post("/api/auth/reset-password-request", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const redirectTo =
      process.env.PASSWORD_RESET_REDIRECT_URL ||
      "https://your-frontend-domain/reset-password";

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo,
    });

    // เพื่อความปลอดภัย ให้ตอบ success เหมือนกันไม่ว่า email จะมีอยู่หรือไม่
    if (error) {
      console.error("resetPasswordForEmail error:", error.message);
      return res.json({
        success: true,
        message: "If this email exists, a reset link has been sent.",
      });
    }

    return res.json({
      success: true,
      message: "If this email exists, a reset link has been sent.",
    });
  } catch (err) {
    console.error("Unexpected reset-password-request error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password using token from email link
 *     tags: [Auth]
 *     description: >
 *       Use the access_token from Supabase's reset-password redirect URL and send it here with the new password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - access_token
 *               - new_password
 *             properties:
 *               access_token:
 *                 type: string
 *                 description: Token from URL query (Supabase recovery)
 *               new_password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Password has been reset
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       400:
 *         description: Missing parameters
 *       401:
 *         description: Invalid or expired token
 *       500:
 *         description: Internal server error
 */
// POST /api/auth/reset-password
// body: { access_token, new_password }
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { access_token, new_password } = req.body;

    if (!access_token || !new_password) {
      return res
        .status(400)
        .json({ error: "access_token and new_password are required" });
    }

    // 1) ใช้ token นี้ถาม Supabase ว่าเป็น user คนไหน
    const { data, error } = await supabase.auth.getUser(access_token);

    if (error || !data || !data.user) {
      console.error(
        "getUser (reset-password) error:",
        error ? error.message : "no user"
      );
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const userId = data.user.id;

    // 2) ใช้ admin API ตั้งรหัสใหม่ให้ user นี้
    const { error: updateErr } = await supabase.auth.admin.updateUserById(
      userId,
      { password: new_password }
    );

    if (updateErr) {
      console.error("updateUserById (reset-password) error:", updateErr.message);
      return res.status(500).json({ error: updateErr.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Unexpected reset-password error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Portfolio API",
      version: "1.0.0",
      description: "API for portfolio + auth using Supabase backend",
    },
    servers: [
      {
        url: "http://localhost:3000",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        User: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            email: { type: "string", format: "email" },
          },
          required: ["id", "email"],
        },
        Profile: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            user_id: { type: "string", format: "uuid" },
            first_name: { type: "string" },
            last_name: { type: "string" },
            about: { type: "string", nullable: true },
            avatar_url: { type: "string", nullable: true },
            is_featured: { type: "boolean" },
            updated_at: { type: "string", format: "date-time", nullable: true },
          },
          required: ["id", "user_id", "first_name", "last_name"],
        },
        Experience: {
          type: "object",
          properties: {
            id: { type: "integer", format: "int64" },
            profile_id: { type: "string", format: "uuid" },
            company: { type: "string" },
            position: { type: "string" },
            start_date: { type: "string", format: "date", nullable: true },
            end_date: { type: "string", format: "date", nullable: true },
            description: { type: "string", nullable: true },
            order_index: { type: "integer", format: "int32" },
          },
          required: ["id", "profile_id", "company", "position", "order_index"],
        },
        ProjectPart: {
          type: "object",
          properties: {
            id: { type: "integer", format: "int64" },
            project_id: { type: "integer", format: "int64" },
            title: { type: "string", nullable: true },
            content: { type: "string", nullable: true },
            image_url: { type: "string", nullable: true },
            link_url: { type: "string", nullable: true },
            kind: { type: "string", nullable: true },
            order_index: { type: "integer", format: "int32" },
          },
          required: ["id", "project_id", "order_index"],
        },
        Project: {
          type: "object",
          properties: {
            id: { type: "integer", format: "int64" },
            profile_id: { type: "string", format: "uuid" },
            title: { type: "string" },
            subtitle: { type: "string", nullable: true },
            cover_image_url: { type: "string", nullable: true },
            order_index: { type: "integer", format: "int32" },
          },
          required: ["id", "profile_id", "title", "order_index"],
        },
        ProjectWithParts: {
          type: "object",
          allOf: [
            { $ref: "#/components/schemas/Project" },
            {
              type: "object",
              properties: {
                parts: {
                  type: "array",
                  items: { $ref: "#/components/schemas/ProjectPart" },
                },
              },
            },
          ],
        },
        MyPortfolio: {
          type: "object",
          properties: {
            profile: { $ref: "#/components/schemas/Profile" },
            experiences: {
              type: "array",
              items: { $ref: "#/components/schemas/Experience" },
            },
            projects: {
              type: "array",
              items: { $ref: "#/components/schemas/ProjectWithParts" },
            },
          },
          required: ["profile", "experiences", "projects"],
        },
        PublicPortfolioItem: {
          type: "object",
          description: "Profile data used for public listing",
          properties: {
            id: { type: "string", format: "uuid" },
            user_id: { type: "string", format: "uuid" },
            first_name: { type: "string" },
            last_name: { type: "string" },
            about: { type: "string", nullable: true },
            avatar_url: { type: "string", nullable: true },
            is_featured: { type: "boolean" },
          },
          required: ["id", "user_id", "first_name", "last_name"],
        },
        PublicPortfoliosResponse: {
          type: "object",
          properties: {
            featured: {
              type: "array",
              items: { $ref: "#/components/schemas/PublicPortfolioItem" },
            },
            list: {
              type: "array",
              items: { $ref: "#/components/schemas/PublicPortfolioItem" },
            },
          },
          required: ["featured", "list"],
        },
        AuthResponse: {
          type: "object",
          properties: {
            token: { type: "string", nullable: true },
            user: { $ref: "#/components/schemas/User" },
            message: { type: "string", nullable: true },
          },
          required: ["user"],
        },
      },
    },
  },
  apis: ["./index.mjs"],
};


const swaggerSpec = swaggerJsdoc(swaggerOptions);

// UI อยู่ที่ /api-docs
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ----------------------
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`✅ Portfolio API listening on port ${PORT}`);
});
