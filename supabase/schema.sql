-- Caja Toro Negro: base de datos en Supabase (Postgres)
-- Correr una sola vez en Supabase > SQL Editor.
-- Columnas en camelCase entre comillas para que coincidan con los campos de la app.

-- ---------- usuarios y roles ----------
create table if not exists public.perfiles (
  id uuid primary key references auth.users(id) on delete cascade,
  nombre text not null default '',
  email text,
  rol text not null default 'lectura' check (rol in ('admin','carga','lectura')),
  activo boolean not null default true,
  creado timestamptz not null default now()
);

-- Cada usuario nuevo de Auth recibe un perfil. El primero que se crea es admin.
create or replace function public.nuevo_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.perfiles (id, email, nombre, rol)
  values (new.id, new.email,
          coalesce(new.raw_user_meta_data->>'nombre', split_part(new.email, '@', 1)),
          case when (select count(*) from public.perfiles) = 0 then 'admin'
               else coalesce(new.raw_user_meta_data->>'rol', 'lectura') end);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.nuevo_perfil();

create or replace function public.mi_rol() returns text
language sql stable security definer set search_path = public as $$
  select rol from public.perfiles where id = auth.uid() and activo
$$;

-- ---------- tablas de la app ----------
create table if not exists public.personal (
  id text primary key default gen_random_uuid()::text,
  nombre text not null, sector text, cargo text, alta date, baja date,
  "sueldoLiquido" numeric, "sueldoNominal" numeric, laudo boolean default false,
  horario text, documento text, telefono text, contrato text, notas text,
  actualizado timestamptz default now()
);
create table if not exists public.movimientos (
  id text primary key default gen_random_uuid()::text,
  fecha date not null, turno text, tipo text not null, categoria text, concepto text,
  persona text, monto numeric not null, moneda text default '$', cotizacion numeric,
  "formaPago" text, notas text, "cargadoPor" text,
  actualizado timestamptz default now()
);
create table if not exists public.adelantos (
  id text primary key default gen_random_uuid()::text,
  empleado text not null, fecha date, turno text, monto numeric not null,
  estado text default 'Entregado', descontado boolean default false, notas text,
  actualizado timestamptz default now()
);
create table if not exists public."cajaFuerte" (
  id text primary key default gen_random_uuid()::text,
  fecha date, tipo text, pesos numeric, dolares numeric, cotizacion numeric, motivo text,
  actualizado timestamptz default now()
);
create table if not exists public.arqueos (
  id text primary key default gen_random_uuid()::text,
  fecha date, turno text, responsable text, "saldoSistema" numeric, contado numeric,
  lotes numeric, comentario text,
  actualizado timestamptz default now()
);
create table if not exists public.propinas (
  id text primary key,            -- fecha_dia / fecha_noche
  fecha date not null, turno text not null, monto numeric,
  actualizado timestamptz default now()
);
create table if not exists public."semanasPropina" (
  id text primary key,            -- lunes de la semana
  acreditada boolean default false, entregada boolean default false,
  actualizado timestamptz default now()
);
create table if not exists public.pagos (
  id text primary key default gen_random_uuid()::text,
  proveedor text not null, tipo text, concepto text, monto numeric, moneda text default '$',
  vencimiento date, estado text default 'Pendiente', "fechaPago" date, notas text,
  actualizado timestamptz default now()
);
create table if not exists public."pendientesDrive" (
  id text primary key,
  tipo text, nombre text, desde text, fecha date, resuelto boolean default false, "resueltoFecha" date,
  actualizado timestamptz default now()
);
create table if not exists public.config (
  id text primary key,            -- 'general'
  cotizacion numeric default 41, "diasAcreditacion" numeric default 15,
  actualizado timestamptz default now()
);

-- ---------- permisos ----------
-- lectura: ve todo. carga: ve y carga. admin: además maneja usuarios.
do $$
declare t text;
begin
  foreach t in array array['personal','movimientos','adelantos','cajaFuerte','arqueos','propinas','semanasPropina','pagos','pendientesDrive','config'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists leer on public.%I', t);
    execute format('drop policy if exists escribir on public.%I', t);
    execute format('create policy leer on public.%I for select to authenticated using (public.mi_rol() is not null)', t);
    execute format('create policy escribir on public.%I for all to authenticated using (public.mi_rol() in (''admin'',''carga'')) with check (public.mi_rol() in (''admin'',''carga''))', t);
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

alter table public.perfiles enable row level security;
drop policy if exists ver_perfiles on public.perfiles;
drop policy if exists admin_perfiles on public.perfiles;
create policy ver_perfiles on public.perfiles for select to authenticated
  using (id = auth.uid() or public.mi_rol() = 'admin');
create policy admin_perfiles on public.perfiles for update to authenticated
  using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');

-- ---------- crear usuarios desde la app (solo admin) ----------
create extension if not exists pgcrypto with schema extensions;
create or replace function public.crear_usuario(p_email text, p_password text, p_nombre text, p_rol text)
returns uuid language plpgsql security definer set search_path = public, auth, extensions as $$
declare uid uuid := gen_random_uuid();
begin
  if public.mi_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede crear usuarios'; end if;
  if p_rol not in ('admin','carga','lectura') then raise exception 'Rol no válido'; end if;
  if length(coalesce(p_password,'')) < 8 then raise exception 'La contraseña tiene que tener al menos 8 caracteres'; end if;
  if exists (select 1 from auth.users where lower(email) = lower(p_email)) then raise exception 'Ya existe un usuario con ese email'; end if;
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', lower(p_email),
    crypt(p_password, gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}', jsonb_build_object('nombre', p_nombre, 'rol', p_rol), now(), now(),
    '', '', '', '');
  insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid, uid::text, jsonb_build_object('sub', uid::text, 'email', lower(p_email), 'email_verified', true),
    'email', now(), now(), now());
  return uid;
end $$;
revoke all on function public.crear_usuario(text,text,text,text) from public, anon;
grant execute on function public.crear_usuario(text,text,text,text) to authenticated;

-- ---------- permisos de acceso a la API ----------
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant execute on function public.mi_rol() to authenticated;
alter table public.movimientos add column if not exists estado text not null default 'Pagado';
alter table public.adelantos add column if not exists origen text not null default 'Fondo de dueños';
alter table public.pagos add column if not exists "pagadoDesde" text;

-- ---------- editar usuarios desde la app (solo admin) ----------
create or replace function public.editar_usuario(p_id uuid, p_nombre text, p_email text, p_password text default null)
returns void language plpgsql security definer set search_path = public, auth, extensions as $$
declare v_email text := lower(trim(p_email));
begin
  if public.mi_rol() is distinct from 'admin' then raise exception 'Solo un administrador puede editar usuarios'; end if;
  if coalesce(trim(p_nombre), '') = '' then raise exception 'Poné el nombre'; end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'El email no es válido'; end if;
  if exists (select 1 from auth.users where lower(email) = v_email and id <> p_id) then raise exception 'Ya existe otro usuario con ese email'; end if;
  if p_password is not null and p_password <> '' and length(p_password) < 8 then raise exception 'La contraseña tiene que tener al menos 8 caracteres'; end if;
  update auth.users set email = v_email,
    encrypted_password = case when coalesce(p_password, '') <> '' then crypt(p_password, gen_salt('bf')) else encrypted_password end,
    raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb) || jsonb_build_object('nombre', trim(p_nombre)),
    updated_at = now()
  where id = p_id;
  if not found then raise exception 'No existe ese usuario'; end if;
  update auth.identities set identity_data = coalesce(identity_data, '{}'::jsonb) || jsonb_build_object('email', v_email), updated_at = now()
  where user_id = p_id and provider = 'email';
  update public.perfiles set nombre = trim(p_nombre), email = v_email where id = p_id;
end $$;
revoke all on function public.editar_usuario(uuid,text,text,text) from public, anon;
grant execute on function public.editar_usuario(uuid,text,text,text) to authenticated;
alter table public.arqueos add column if not exists cuenta text not null default 'Fondo de dueños', add column if not exists "saldoUsd" numeric, add column if not exists "contadoUsd" numeric;
