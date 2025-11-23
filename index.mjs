// index.mjs
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

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

// ----------------------
// Helper: Auth middleware
// ----------------------
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

  const token = authHeader.split(" ")[1];

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    console.error("Auth error:", error?.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  req.user = data.user; // { id, email, ... }
  req.token = token;
  next();
}

// ----------------------
// Auth endpoints
// ----------------------

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

    // 1) Sign up user in Supabase Auth
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

    // ถ้าตั้งค่าให้ต้องยืนยัน email session อาจจะ null
    // ถ้าอยากให้ dev flow ง่าย ลอง signIn อีกที
    if (!session) {
      const { data: loginData, error: loginError } =
        await supabase.auth.signInWithPassword({
          email,
          password,
        });

      if (loginError) {
        console.error("Auto-login after signUp error:", loginError.message);
        return res.status(200).json({
          // สมัครสำเร็จ แต่ไม่ได้ออก token
          token: null,
          user: {
            id: user.id,
            email: user.email,
          },
          message:
            "User registered. Please verify email (if email confirmation is enabled).",
        });
      }

      session = loginData.session;
    }

    const token = session?.access_token;
    if (!token || !user) {
      return res.status(500).json({
        error: "User created but no session token. Check Supabase auth config.",
      });
    }

    // 2) Ensure profiles row exists for this user
    //    ถ้ายังไม่มี profile ให้สร้าง
    const { data: existingProfile, error: profileSelectError } = await supabase
      .from("profiles")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle();

    if (profileSelectError) {
      console.error("Profile select error:", profileSelectError.message);
    }

    if (!existingProfile) {
      const { error: profileInsertError } = await supabase
        .from("profiles")
        .insert({
          user_id: user.id,
          first_name: "",
          last_name: "",
          about: "",
        });

      if (profileInsertError) {
        console.error("Profile insert error:", profileInsertError.message);
        // ไม่ถึงกับต้อง fail ทั้ง login แต่อย่างน้อย log ไว้
      }
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
    const token = session?.access_token;

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

// POST /api/auth/logout
// (ตรงนี้เราทำแค่ mock, ไม่ได้ revoke token จริง)
// Frontend แค่ลบ token ฝั่งตัวเองก็พอ
app.post("/api/auth/logout", requireAuth, (req, res) => {
  return res.json({ success: true });
});

// ----------------------
// Public portfolio endpoints
// ----------------------

// GET /api/public/portfolios
// { featured: [...], list: [...] }
app.get("/api/public/portfolios", async (req, res) => {
  try {
    // featured portfolios
    const { data: featured, error: fErr } = await supabase
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

    // all portfolios (คุณจะ filter เพิ่มเติมก็ได้ เช่น exclude featured)
    const { data: all, error: aErr } = await supabase
      .from("profiles")
      .select(
        "id, user_id, first_name, last_name, about, avatar_url, is_featured"
      )
      .order("updated_at", { ascending: false });

    if (aErr) {
      console.error("All profiles error:", aErr.message);
      return res.status(500).json({ error: aErr.message });
    }

    return res.json({
      featured: featured ?? [],
      list: all ?? [],
    });
  } catch (err) {
    console.error("Unexpected public portfolios error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ----------------------
// Authenticated portfolio endpoints
// ----------------------

// GET /api/me/portfolio
// -> { profile, experiences, projects }
app.get("/api/me/portfolio", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1) Get or create profile for this user
    let { data: profile, error: pErr } = await supabase
      .from("profiles")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    if (pErr) {
      console.error("Profile select error:", pErr.message);
      return res.status(500).json({ error: pErr.message });
    }

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
        return res.status(500).json({ error: insErr.message });
      }
      profile = inserted;
    }

    const profileId = profile.id;

    // 2) experiences
    const { data: experiences, error: eErr } = await supabase
      .from("experiences")
      .select("*")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (eErr) {
      console.error("Experiences error:", eErr.message);
      return res.status(500).json({ error: eErr.message });
    }

    // 3) projects + parts
    const { data: projects, error: prErr } = await supabase
      .from("projects")
      .select("id, profile_id, title, subtitle, cover_image_url, order_index")
      .eq("profile_id", profileId)
      .order("order_index", { ascending: true });

    if (prErr) {
      console.error("Projects error:", prErr.message);
      return res.status(500).json({ error: prErr.message });
    }

    let projectsWithParts = projects ?? [];
    if (projectsWithParts.length > 0) {
      const projectIds = projectsWithParts.map((p) => p.id);

      const { data: parts, error: partsErr } = await supabase
        .from("project_parts")
        .select("*")
        .in("project_id", projectIds)
        .order("order_index", { ascending: true });

      if (partsErr) {
        console.error("Project parts error:", partsErr.message);
        return res.status(500).json({ error: partsErr.message });
      }

      const partsByProject = {};
      for (const part of parts ?? []) {
        if (!partsByProject[part.project_id]) {
          partsByProject[part.project_id] = [];
        }
        partsByProject[part.project_id].push(part);
      }

      projectsWithParts = projectsWithParts.map((p) => ({
        ...p,
        parts: partsByProject[p.id] ?? [],
      }));
    }

    return res.json({
      profile,
      experiences: experiences ?? [],
      projects: projectsWithParts,
    });
  } catch (err) {
    console.error("Unexpected me/portfolio error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /api/me/profile
// body: { first_name, last_name, about, avatar_url, is_featured }
app.put("/api/me/profile", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { first_name, last_name, about, avatar_url, is_featured } = req.body;

    // อัปเดตโดยอิง user_id
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
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`✅ Portfolio API listening on port ${PORT}`);
});
