export function UserMenu({ name }: { name: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-sm text-zinc-700">{name}</span>
      <form action="/auth/sign-out" method="post">
        <button
          type="submit"
          className="rounded-md border border-zinc-300 px-3 py-1 text-sm font-medium hover:bg-zinc-100"
        >
          Sign out
        </button>
      </form>
    </div>
  );
}
