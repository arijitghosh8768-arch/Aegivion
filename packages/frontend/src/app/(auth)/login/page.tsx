"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useAuthStore } from "@/store/auth-store";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const router = useRouter();
  const login = useAuthStore((state) => state.login);

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormValues) => {
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      login({ id: "1", email: data.email, name: "Security Admin", role: "admin" }, "mock-jwt-token");
      toast.success("Login successful!");
      router.push("/");
    } catch (error) {
      toast.error("Invalid credentials");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0F172A] p-4">
      <div className="w-full max-w-md bg-[#1E293B] border border-slate-700 rounded-lg p-8">
        <div className="text-center mb-6">
          <h1 className="text-3xl font-bold text-blue-500">Aegivion</h1>
          <p className="text-slate-400 mt-2">Sign in to your security dashboard</p>
        </div>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <input 
              placeholder="admin@aegivion.com" 
              {...register("email")} 
              className="w-full px-3 py-2 rounded bg-[#0F172A] border border-slate-700 text-slate-100 text-sm focus:outline-none"
            />
            {errors.email && <p className="text-xs text-red-500">{errors.email.message}</p>}
          </div>
          <div className="space-y-2">
            <input 
              type="password" 
              placeholder="••••••••" 
              {...register("password")} 
              className="w-full px-3 py-2 rounded bg-[#0F172A] border border-slate-700 text-slate-100 text-sm focus:outline-none"
            />
            {errors.password && <p className="text-xs text-red-500">{errors.password.message}</p>}
          </div>
          <button 
            type="submit" 
            className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm font-semibold transition-all" 
            disabled={isSubmitting}
          >
            {isSubmitting ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
