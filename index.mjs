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

// POST /api/auth/logout
app.post("/api/auth/logout", requireAuth, (req, res) => {
  // ใช้ token-based stateless -> แค่ให้ frontend ลบ token ก็พอ
  return res.json({ success: true });
});

// ----------------------
// Public portfolios
// ----------------------

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

// PUT /api/me/profile
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

// ----------------------
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`✅ Portfolio API listening on port ${PORT}`);
});
