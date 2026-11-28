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

-- 20/11: vínculo de descuentos con pagos
alter table movimientos add column if not exists "pagoId" text;
alter table "cajaFuerte" add column if not exists "pagoId" text;
alter table movimientos add column if not exists "semanaPropina" text;
alter table "cajaFuerte" add column if not exists "semanaPropina" text;

-- 20/11: fecha en que se descontó el adelanto
alter table adelantos add column if not exists "descontadoFecha" date;

-- Permisos por sección (21/11/2026)
-- nivel: 0 sin acceso, 1 ver, 2 cargar, 3 editar. Admin = 3 en todo.
-- Si perfiles.permisos.secciones no existe, vale el rol: carga = editar, lectura = ver.
create or replace function public.nivel(sec text) returns int
language sql stable security definer set search_path = public as $$
  select case
    when p.rol = 'admin' then 3
    when jsonb_typeof(p.permisos->'secciones') = 'object' then
      case p.permisos->'secciones'->>sec when 'editar' then 3 when 'cargar' then 2 when 'ver' then 1 else 0 end
    when p.rol = 'carga' then 3
    when p.rol = 'lectura' then 1
    else 0 end
  from public.perfiles p where p.id = auth.uid() and p.activo
$$;
create or replace function public.privado(grupo text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(p.rol = 'admin' or coalesce((p.permisos->'privado'->>grupo)::boolean, false), false)
  from public.perfiles p where p.id = auth.uid() and p.activo
$$;
grant execute on function public.nivel(text) to authenticated;
grant execute on function public.privado(text) to authenticated;

-- datos privados del personal: una fila por persona y campo
create table if not exists public."personalPrivado" (
  id text primary key,
  persona text not null references public.personal(id) on delete cascade,
  campo text not null check (campo in ('sueldoLiquido','sueldoNominal','documento','telefono','cuenta')),
  valor text not null,
  actualizado timestamptz default now()
);
create or replace function public.grupo_privado(campo text) returns text language sql immutable as $$
  select case when campo in ('sueldoLiquido','sueldoNominal') then 'sueldos' when campo in ('documento','telefono') then 'documentos' else 'cuentas' end
$$;
grant execute on function public.grupo_privado(text) to authenticated;
alter table public."personalPrivado" enable row level security;
grant select, insert, update, delete on public."personalPrivado" to authenticated;
-- (acá se copiaron los datos privados existentes desde personal; no van en el repo)
alter table public.personal drop column if exists "sueldoLiquido", drop column if exists "sueldoNominal", drop column if exists documento, drop column if exists telefono;

-- políticas
do $$ declare t text; begin
  foreach t in array array['movimientos','cajaFuerte','arqueos','adelantos','propinas','semanasPropina','personal','pagos','pendientesDrive','config','personalPrivado'] loop
    execute format('drop policy if exists leer on public.%I', t);
    execute format('drop policy if exists escribir on public.%I', t);
    execute format('drop policy if exists p_sel on public.%I', t);
    execute format('drop policy if exists p_ins on public.%I', t);
    execute format('drop policy if exists p_upd on public.%I', t);
    execute format('drop policy if exists p_del on public.%I', t);
  end loop;
end $$;

-- secciones simples
do $$ declare r record; begin
  for r in select * from (values ('propinas','propinas'),('semanasPropina','propinas'),('pagos','pagos')) v(t, s) loop
    execute format('create policy p_sel on public.%I for select to authenticated using (public.nivel(%L) >= 1)', r.t, r.s);
    execute format('create policy p_ins on public.%I for insert to authenticated with check (public.nivel(%L) >= 2)', r.t, r.s);
    execute format('create policy p_upd on public.%I for update to authenticated using (public.nivel(%L) >= 3) with check (public.nivel(%L) >= 3)', r.t, r.s, r.s);
    execute format('create policy p_del on public.%I for delete to authenticated using (public.nivel(%L) >= 3)', r.t, r.s);
  end loop;
end $$;

-- movimientos (Fondo de dueños) y cajaFuerte (Retiros): además, un editor de Pagos maneja lo que sale de un pago
do $$ declare r record; begin
  for r in select * from (values ('movimientos','caja'),('cajaFuerte','fuerte')) v(t, s) loop
    execute format('create policy p_sel on public.%I for select to authenticated using (public.nivel(%L) >= 1 or ("pagoId" is not null and public.nivel(''pagos'') >= 3))', r.t, r.s);
    execute format('create policy p_ins on public.%I for insert to authenticated with check (public.nivel(%L) >= 2 or ("pagoId" is not null and public.nivel(''pagos'') >= 3))', r.t, r.s);
    execute format('create policy p_upd on public.%I for update to authenticated using (public.nivel(%L) >= 3) with check (public.nivel(%L) >= 3)', r.t, r.s, r.s);
    execute format('create policy p_del on public.%I for delete to authenticated using (public.nivel(%L) >= 3 or ("pagoId" is not null and public.nivel(''pagos'') >= 3))', r.t, r.s);
  end loop;
end $$;

-- arqueos: mismo permiso que su fondo
create policy p_sel on public.arqueos for select to authenticated using (public.nivel(case when cuenta = 'Retiros de caja' then 'fuerte' else 'caja' end) >= 1);
create policy p_ins on public.arqueos for insert to authenticated with check (public.nivel(case when cuenta = 'Retiros de caja' then 'fuerte' else 'caja' end) >= 2);
create policy p_upd on public.arqueos for update to authenticated using (public.nivel(case when cuenta = 'Retiros de caja' then 'fuerte' else 'caja' end) >= 3) with check (public.nivel(case when cuenta = 'Retiros de caja' then 'fuerte' else 'caja' end) >= 3);
create policy p_del on public.arqueos for delete to authenticated using (public.nivel(case when cuenta = 'Retiros de caja' then 'fuerte' else 'caja' end) >= 3);

-- adelantos: los leen también quienes ven los fondos (para el saldo)
create policy p_sel on public.adelantos for select to authenticated using (greatest(public.nivel('adelantos'), public.nivel('caja'), public.nivel('fuerte')) >= 1);
create policy p_ins on public.adelantos for insert to authenticated with check (public.nivel('adelantos') >= 2);
create policy p_upd on public.adelantos for update to authenticated using (public.nivel('adelantos') >= 3) with check (public.nivel('adelantos') >= 3);
create policy p_del on public.adelantos for delete to authenticated using (public.nivel('adelantos') >= 3);

-- personal: nombres visibles también para quien carga adelantos
create policy p_sel on public.personal for select to authenticated using (greatest(public.nivel('personal'), public.nivel('adelantos')) >= 1);
create policy p_ins on public.personal for insert to authenticated with check (public.nivel('personal') >= 2);
create policy p_upd on public.personal for update to authenticated using (public.nivel('personal') >= 3) with check (public.nivel('personal') >= 3);
create policy p_del on public.personal for delete to authenticated using (public.nivel('personal') >= 3);

-- datos privados: sección Personal + casilla del grupo
create policy p_sel on public."personalPrivado" for select to authenticated using (public.nivel('personal') >= 1 and public.privado(public.grupo_privado(campo)));
create policy p_ins on public."personalPrivado" for insert to authenticated with check (public.nivel('personal') >= 2 and public.privado(public.grupo_privado(campo)));
create policy p_upd on public."personalPrivado" for update to authenticated using (public.nivel('personal') >= 3 and public.privado(public.grupo_privado(campo))) with check (public.nivel('personal') >= 3 and public.privado(public.grupo_privado(campo)));
create policy p_del on public."personalPrivado" for delete to authenticated using (public.nivel('personal') >= 3 and public.privado(public.grupo_privado(campo)));

-- pendientes de Drive: cualquiera que cargue algo deja aviso; solo admin los ve y resuelve
create policy p_sel on public."pendientesDrive" for select to authenticated using (public.mi_rol() is not null);
create policy p_ins on public."pendientesDrive" for insert to authenticated with check (public.mi_rol() is not null);
create policy p_upd on public."pendientesDrive" for update to authenticated using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');
create policy p_del on public."pendientesDrive" for delete to authenticated using (public.mi_rol() = 'admin');

-- config: todos leen, solo admin cambia
create policy p_sel on public.config for select to authenticated using (public.mi_rol() is not null);
create policy p_ins on public.config for insert to authenticated with check (public.mi_rol() = 'admin');
create policy p_upd on public.config for update to authenticated using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');
create policy p_del on public.config for delete to authenticated using (public.mi_rol() = 'admin');

do $$ begin
  begin execute 'alter publication supabase_realtime add table public."personalPrivado"'; exception when duplicate_object then null; end;
end $$;

-- formas de pago dentro de un pago (23/11/2026)
alter table public.pagos add column if not exists formas jsonb not null default '[]'::jsonb;

-- pagos que se repiten todos los meses (23/11/2026)
alter table public.pagos add column if not exists repetir text;

-- adelantos unidos a la ficha de la persona (24/11/2026)
alter table public.adelantos add column if not exists "personaId" text references public.personal(id) on delete set null;
update public.adelantos a set "personaId" = p.id from public.personal p where p.nombre = a.empleado and a."personaId" is null;

-- Altas y bajas para BPS (25/11/2026)
alter table public.personal
  add column if not exists "bajaMotivo" text,
  add column if not exists "altaBps" date,
  add column if not exists "altaBpsPor" text,
  add column if not exists "bajaBps" date,
  add column if not exists "bajaBpsPor" text;

-- datos privados nuevos: nacimiento (grupo documentos), email y domicilio (grupo contacto)
alter table public."personalPrivado" drop constraint if exists "personalPrivado_campo_check";
alter table public."personalPrivado" add constraint "personalPrivado_campo_check"
  check (campo in ('sueldoLiquido','sueldoNominal','documento','telefono','cuenta','nacimiento','email','domicilio'));
create or replace function public.grupo_privado(campo text) returns text language sql immutable as $$
  select case when campo in ('sueldoLiquido','sueldoNominal') then 'sueldos'
              when campo in ('documento','telefono','nacimiento') then 'documentos'
              when campo in ('email','domicilio') then 'contacto'
              else 'cuentas' end
$$;

-- marcar una alta o baja como procesada en BPS: admin o quien tenga permisos.bps
create or replace function public.marcar_bps(p_persona text, p_tipo text, p_deshacer boolean default false)
returns void language plpgsql security definer set search_path = public as $$
declare yo record;
begin
  select * into yo from public.perfiles where id = auth.uid() and activo;
  if yo is null or not (yo.rol = 'admin' or coalesce((yo.permisos->>'bps')::boolean, false)) then
    raise exception 'Sin permiso para marcar BPS';
  end if;
  if p_tipo = 'alta' then
    update public.personal set "altaBps" = case when p_deshacer then null else current_date end,
      "altaBpsPor" = case when p_deshacer then null else yo.nombre end, actualizado = now() where id = p_persona;
  elsif p_tipo = 'baja' then
    update public.personal set "bajaBps" = case when p_deshacer then null else current_date end,
      "bajaBpsPor" = case when p_deshacer then null else yo.nombre end, actualizado = now() where id = p_persona;
  else
    raise exception 'Tipo inválido';
  end if;
end $$;
revoke all on function public.marcar_bps(text, text, boolean) from public;
grant execute on function public.marcar_bps(text, text, boolean) to authenticated;

-- Ficha de persona (25/11/2026): apellido aparte, carnés, contacto de emergencia y banco aparte
alter table public.personal
  add column if not exists apellido text,
  add column if not exists "carneSalud" date,
  add column if not exists "carneManipulador" date;

alter table public."personalPrivado" drop constraint if exists "personalPrivado_campo_check";
alter table public."personalPrivado" add constraint "personalPrivado_campo_check"
  check (campo in ('sueldoLiquido','sueldoNominal','documento','telefono','cuenta','banco','nacimiento','email','domicilio','emergenciaNombre','emergenciaTel'));
create or replace function public.grupo_privado(campo text) returns text language sql immutable as $$
  select case when campo in ('sueldoLiquido','sueldoNominal') then 'sueldos'
              when campo in ('documento','telefono','nacimiento') then 'documentos'
              when campo in ('email','domicilio','emergenciaNombre','emergenciaTel') then 'contacto'
              else 'cuentas' end
$$;

-- Hora de cada arqueo (25/11/2026)
alter table public.arqueos add column if not exists creado timestamptz default now();

-- Temas internos (25/11/2026): cosas a resolver que no son pagos
create table if not exists public.temas (
  id text primary key default gen_random_uuid()::text,
  titulo text not null, detalle text, responsable text, "fechaLimite" date,
  estado text not null default 'Abierto' check (estado in ('Abierto','Resuelto')), "resueltoFecha" date,
  creado timestamptz default now(), actualizado timestamptz default now()
);
alter table public.temas enable row level security;
grant select, insert, update, delete on public.temas to authenticated;
drop policy if exists p_sel on public.temas; drop policy if exists p_ins on public.temas;
drop policy if exists p_upd on public.temas; drop policy if exists p_del on public.temas;
create policy p_sel on public.temas for select to authenticated using (public.nivel('temas') >= 1);
create policy p_ins on public.temas for insert to authenticated with check (public.nivel('temas') >= 2);
create policy p_upd on public.temas for update to authenticated using (public.nivel('temas') >= 3) with check (public.nivel('temas') >= 3);
create policy p_del on public.temas for delete to authenticated using (public.nivel('temas') >= 3);
do $$ begin execute 'alter publication supabase_realtime add table public.temas'; exception when duplicate_object then null; end $$;
alter table "cajaFuerte" add column if not exists estado text;
