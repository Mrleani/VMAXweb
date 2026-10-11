import { createClient as createServerClient } from "@supabase/supabase-js";

export function createServerClientInstance() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return createServerClient("https://dummy.supabase.co", "dummy-key", {
      auth: { persistSession: false },
    });
  }

  return createServerClient(supabaseUrl, supabaseAnonKey, {
    auth: { persistSession: false },
  });
}
