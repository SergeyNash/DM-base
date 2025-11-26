import { createClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL;
const serviceKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_ANON_KEY;

if (!url || !serviceKey) {
  throw new Error(
    "SUPABASE_URL и ключ (SUPABASE_SERVICE_ROLE_KEY или SUPABASE_ANON_KEY) должны быть заданы"
  );
}

export const supabase = createClient(url, serviceKey, {
  auth: {
    persistSession: false,
  },
});

