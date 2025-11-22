import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Supabase client (ใช้ service role key)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// 1) get profile หลัก (เอาแค่ตัวเดียวก่อน)
app.get("/api/profile", async (req, res) => {
  const { data, error } = await supabase
    .from("profiles")
    .select("*")
    .limit(1)
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// 2) get experiences ทั้งหมดของ profile
app.get("/api/experiences/:profileId", async (req, res) => {
  const { profileId } = req.params;

  const { data, error } = await supabase
    .from("experiences")
    .select("*")
    .eq("profile_id", profileId)
    .order("order_index", { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// 3) get projects + parts ของ profile
app.get("/api/projects/:profileId", async (req, res) => {
  const { profileId } = req.params;

  const { data: projects, error: projectError } = await supabase
    .from("projects")
    .select("*")
    .eq("profile_id", profileId)
    .order("order_index", { ascending: true });

  if (projectError) {
    return res.status(500).json({ error: projectError.message });
  }

  const projectIds = projects.map((p) => p.id);
  if (projectIds.length === 0) {
    return res.json([]);
  }

  const { data: parts, error: partsError } = await supabase
    .from("project_parts")
    .select("*")
    .in("project_id", projectIds)
    .order("order_index", { ascending: true });

  if (partsError) {
    return res.status(500).json({ error: partsError.message });
  }

  // รวม parts เข้าไปในแต่ละ project
  const partsByProject = {};
  for (const part of parts) {
    partsByProject[part.project_id] ??= [];
    partsByProject[part.project_id].push(part);
  }

  const result = projects.map((p) => ({
    ...p,
    parts: partsByProject[p.id] ?? [],
  }));

  res.json(result);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Portfolio API listening on port ${port}`);
});
