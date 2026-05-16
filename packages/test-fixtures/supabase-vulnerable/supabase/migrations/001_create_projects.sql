create table public.projects (
  id uuid primary key,
  owner_id uuid not null,
  name text not null
);

