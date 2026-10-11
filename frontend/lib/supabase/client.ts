import { createClient as createSupabaseClient } from "@supabase/supabase-js";

export function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return createSupabaseClient("https://dummy.supabase.co", "dummy-key");
  }

  return createSupabaseClient(supabaseUrl, supabaseAnonKey);
}
