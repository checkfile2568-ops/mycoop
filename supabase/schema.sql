create table public.mycoop_vault (
 id smallint primary key check(id=1),
 payload jsonb not null,
 auth_salt text not null,
 auth_hash text not null,
 auth_version integer not null default 1,
 revision bigint not null default 1,
 updated_at timestamptz not null default now()
);
create table public.mycoop_sessions (
 token_hash text primary key,
 auth_version integer not null,
 expires_at timestamptz not null
);
create index mycoop_sessions_expires_idx on public.mycoop_sessions(expires_at);
create table public.mycoop_rate_limits (
 bucket text primary key,
 hits integer not null,
 expires_at timestamptz not null
);
create index mycoop_rate_limits_expires_idx on public.mycoop_rate_limits(expires_at);
alter table public.mycoop_vault enable row level security;
alter table public.mycoop_sessions enable row level security;
alter table public.mycoop_rate_limits enable row level security;
revoke all on public.mycoop_vault,public.mycoop_sessions,public.mycoop_rate_limits from public,anon,authenticated;
grant select,insert,update,delete on public.mycoop_vault,public.mycoop_sessions,public.mycoop_rate_limits to service_role;
create function public.mycoop_take_attempt(p_bucket text,p_limit integer,p_expires timestamptz)
returns boolean language plpgsql security invoker set search_path='' as $$
declare count_now integer;
begin
 insert into public.mycoop_rate_limits(bucket,hits,expires_at) values(p_bucket,1,p_expires)
 on conflict(bucket) do update set hits=public.mycoop_rate_limits.hits+1
 returning hits into count_now;
 return count_now<=p_limit;
end;
$$;
revoke all on function public.mycoop_take_attempt(text,integer,timestamptz) from public,anon,authenticated;
grant execute on function public.mycoop_take_attempt(text,integer,timestamptz) to service_role;

create policy deny_direct_client_access on public.mycoop_vault for all to anon,authenticated using(false) with check(false);
create policy deny_direct_client_access on public.mycoop_sessions for all to anon,authenticated using(false) with check(false);
create policy deny_direct_client_access on public.mycoop_rate_limits for all to anon,authenticated using(false) with check(false);
