export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex-1 w-full min-w-0">
      {children}
    </div>
  );
}
