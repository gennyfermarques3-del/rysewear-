// Login, senha e recuperação de acesso da RYSE WEAR.
// Todas as regras de segurança ficam aqui e no esquema "security" do banco (fora da API pública):
// - senha guardada com Argon2id (hash-wasm), nunca em texto puro;
// - 3 tentativas erradas bloqueiam a conta por 5 min, com tempo dobrando nas reincidências;
// - limite por IP e alertas de padrões automatizados (funções security.* no banco);
// - a senha do Auth da Supabase vira um valor aleatório: login direto pela API do Auth não serve;
// - toda sessão precisa estar registrada em security.sessions, senão o banco nega os dados.
import postgres from 'npm:postgres@3.4.5';
import { createClient } from 'npm:@supabase/supabase-js@2.49.4';
import { argon2id, argon2Verify } from 'npm:hash-wasm@4.12.0';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!;
const sql = postgres(Deno.env.get('SUPABASE_DB_URL')!, { prepare: false, max: 3, idle_timeout: 20 });
const opts = { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } };
const admin = createClient(SUPABASE_URL, SERVICE_KEY, opts);

const MIN_LEN = 8, MAX_LEN = 128;
const ARGON = { parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32, outputType: 'encoded' as const };
const ORIGIN_OK = /^https:\/\/ryse-wear(-[a-z0-9]+-gennyfer)?\.vercel\.app$/;

function cors(req: Request): Record<string, string> {
  const o = req.headers.get('origin') || '';
  return ORIGIN_OK.test(o)
    ? { 'Access-Control-Allow-Origin': o, 'Vary': 'Origin', 'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
    : { 'Vary': 'Origin' };
}
const json = (req: Request, status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...cors(req) } });

function clientIp(req: Request): string {
  return req.headers.get('cf-connecting-ip')?.trim() || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'desconhecido';
}
function claims(token: string): Record<string, any> {
  const p = token.split('.')[1] || '';
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(p.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((p.length + 3) % 4)), c => c.charCodeAt(0))));
}
const randomSecret = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(48))));
const hashPassword = (password: string) => argon2id({ password, salt: crypto.getRandomValues(new Uint8Array(16)), ...ARGON });

let dummyHash: string | null = null;
async function dummyVerify(password: string) { // mesmo custo de tempo quando o e-mail não existe
  dummyHash ??= await hashPassword(randomSecret());
  await argon2Verify({ password, hash: dummyHash });
}

const COMMON = ['12345678', '123456789', '1234567890', 'password', 'senha123', 'qwertyui', 'qwerty123', 'abc12345', 'iloveyou', 'admin123', 'rysewear', '11111111', '00000000', 'mudar123', 'brasil123', 'senhasenha', 'password1', 'princesa', 'flamengo', 'corinthians'];
async function passwordProblem(pw: string, email: string): Promise<string | null> {
  if (pw.length < MIN_LEN) return `A senha precisa ter pelo menos ${MIN_LEN} caracteres.`;
  if (pw.length > MAX_LEN) return `A senha pode ter no máximo ${MAX_LEN} caracteres.`;
  const low = pw.toLowerCase(), local = email.split('@')[0].toLowerCase();
  if (new Set(pw).size < 4) return 'A senha repete poucos caracteres. Escolha uma mais variada.';
  if (/^\d+$/.test(pw)) return 'A senha não pode ter só números.';
  if (COMMON.some(c => low === c || low.startsWith(c) && low.length <= c.length + 2)) return 'Essa senha é muito comum. Escolha outra.';
  if (local.length >= 4 && low.includes(local)) return 'A senha não pode conter o seu e-mail.';
  if ('01234567890abcdefghijklmnopqrstuvwxyz'.includes(low) || 'qwertyuiopasdfghjklzxcvbnm'.includes(low)) return 'Sequências de teclado não são aceitas.';
  try { // senhas vazadas (Have I Been Pwned, k-anonimato: só os 5 primeiros caracteres do hash saem daqui)
    const h = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(pw)))).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 3000);
    const r = await fetch(`https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`, { headers: { 'Add-Padding': 'true' }, signal: ctl.signal });
    clearTimeout(t);
    if (r.ok) {
      const hit = (await r.text()).split('\n').find(l => l.startsWith(h.slice(5)));
      if (hit && Number(hit.split(':')[1]) > 0) return 'Essa senha já apareceu em vazamentos de dados na internet. Escolha outra.';
    }
  } catch { /* serviço externo fora do ar: as outras regras continuam valendo */ }
  return null;
}

async function mintSession(email: string) {
  const { data: link, error: e1 } = await admin.auth.admin.generateLink({ type: 'magiclink', email });
  if (e1 || !link?.properties?.hashed_token) throw new Error('link: ' + (e1?.message || 'sem token'));
  const pub = createClient(SUPABASE_URL, ANON_KEY, opts);
  const { data, error: e2 } = await pub.auth.verifyOtp({ type: 'magiclink', token_hash: link.properties.hashed_token });
  if (e2 || !data?.session) throw new Error('sessao: ' + (e2?.message || 'sem sessão'));
  return data.session;
}

async function login(req: Request, body: any) {
  const email = String(body.email || '').trim().toLowerCase(), password = String(body.password ?? '');
  const ip = clientIp(req), ua = (req.headers.get('user-agent') || '').slice(0, 300);
  if (!email || !password || email.length > 254 || password.length > MAX_LEN * 2) return json(req, 400, { error: 'dados_invalidos', message: 'Informe e-mail e senha.' });

  const [lk] = await sql`select * from security.check_lock(${email}, ${ip})`;
  if (lk.blocked) {
    await sql`select security.log_blocked(${email}, ${ip}, ${ua}, ${lk.scope})`;
    return json(req, 429, { error: 'bloqueado', retry_after: lk.retry_after, message: 'Muitas tentativas. Aguarde para tentar de novo.' });
  }

  const [u] = await sql`
    select u.id, u.encrypted_password, c.hash, c.must_change, coalesce(m.must_reset, false) as must_reset, (m.email is not null) as member
    from auth.users u
    left join security.credentials c on c.user_id = u.id
    left join public.members m on lower(m.email) = lower(u.email)
    where lower(u.email) = ${email} and u.deleted_at is null limit 1`;

  let ok = false, legacy = false;
  if (u?.member && u.hash) ok = await argon2Verify({ password, hash: u.hash });
  else if (u?.member && u.encrypted_password) {
    const [r] = await sql`select (${u.encrypted_password}::text = extensions.crypt(${password}, ${u.encrypted_password}::text)) as ok`;
    ok = r.ok; legacy = true;
  } else await dummyVerify(password);

  if (!ok) {
    const [r] = await sql`select security.register_fail(${email}, ${u?.id ?? null}, ${ip}, ${ua}) as r`;
    return r.r.locked
      ? json(req, 429, { error: 'bloqueado', retry_after: r.r.retry_after, message: 'Muitas tentativas. Aguarde para tentar de novo.' })
      : json(req, 401, { error: 'credenciais', message: 'E-mail ou senha incorretos.' });
  }

  const mustChange = !!u.must_change || !!u.must_reset;
  if (legacy) { // primeira entrada no sistema novo: mantém a senha atual, só migra para Argon2id e desativa a senha do Auth.
    // A política (8+ caracteres, não vazada) vale para senhas criadas ou trocadas daqui em diante.
    await sql`insert into security.credentials (user_id, hash, must_change) values (${u.id}, ${await hashPassword(password)}, ${mustChange})
              on conflict (user_id) do update set hash = excluded.hash, must_change = excluded.must_change, changed_at = now()`;
    await sql`insert into security.audit (kind, email, user_id, ip, ua, detail) values ('password_migrated', ${email}, ${u.id}, ${ip}, ${ua}, ${sql.json({ senha_mantida: true })})`;
    const { error } = await admin.auth.admin.updateUserById(u.id, { password: randomSecret() });
    if (error) throw new Error('auth: ' + error.message);
  }

  const session = await mintSession(email);
  const sid = claims(session.access_token).session_id;
  await sql`select security.register_success(${u.id}, ${email}, ${ip}, ${ua}, ${sid}::uuid, ${mustChange ? 'password_change' : 'full'})`;
  return json(req, 200, {
    must_change: mustChange,
    session: { access_token: session.access_token, refresh_token: session.refresh_token, expires_in: session.expires_in, expires_at: session.expires_at, token_type: session.token_type },
  });
}

async function setPassword(req: Request, body: any) {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const ip = clientIp(req), ua = (req.headers.get('user-agent') || '').slice(0, 300);
  if (!token) return json(req, 401, { error: 'sem_sessao' });
  const { data: got } = await admin.auth.getUser(token);
  const user = got?.user;
  if (!user?.email) return json(req, 401, { error: 'sem_sessao', message: 'Sessão inválida. Entre de novo.' });
  const c = claims(token), email = user.email.toLowerCase();
  const [st] = await sql`select security.session_state(${c.session_id}::uuid, ${user.id}::uuid) as st`;
  const now = Date.now() / 1000;
  const viaEmail = Array.isArray(c.amr) && c.amr.some((a: any) => ['recovery', 'invite', 'otp'].includes(a.method) && now - a.timestamp < 3600) && st.st === 'unknown';
  if (!['active', 'password_change'].includes(st.st) && !viaEmail) return json(req, 403, { error: 'sessao', message: 'Sessão expirada. Entre de novo.' });
  const [m] = await sql`select 1 from public.members where lower(email) = ${email}`;
  if (!m) return json(req, 403, { error: 'sem_acesso', message: 'Este e-mail não tem acesso à loja.' });

  const password = String(body.password ?? '');
  const problem = await passwordProblem(password, email);
  if (problem) return json(req, 400, { error: 'senha_fraca', message: problem });
  const [cur] = await sql`select hash from security.credentials where user_id = ${user.id}`;
  if (cur?.hash && await argon2Verify({ password, hash: cur.hash })) return json(req, 400, { error: 'senha_repetida', message: 'Escolha uma senha diferente da atual.' });

  await sql`insert into security.credentials (user_id, hash, must_change) values (${user.id}, ${await hashPassword(password)}, false)
            on conflict (user_id) do update set hash = excluded.hash, must_change = false, changed_at = now()`;
  await sql`update public.members set must_reset = false where lower(email) = ${email}`;
  const { error } = await admin.auth.admin.updateUserById(user.id, { password: randomSecret() });
  if (error) throw new Error('auth: ' + error.message);
  const [rv] = await sql`select security.revoke_sessions(${user.id}::uuid, 'senha_alterada') as n`;
  await sql`insert into security.audit (kind, email, user_id, ip, ua, detail) values ('password_changed', ${email}, ${user.id}, ${ip}, ${ua}, ${sql.json({ sessoes_encerradas: rv.n, via_email: viaEmail })})`;
  return json(req, 200, { ok: true });
}

async function requestReset(req: Request, body: any) {
  const email = String(body.email || '').trim().toLowerCase(), ip = clientIp(req);
  const generic = json(req, 200, { ok: true, message: 'Se este e-mail tiver acesso, o link chega em instantes.' });
  if (!email || email.length > 254 || !email.includes('@')) return generic;
  const [r] = await sql`select security.reset_allowed(${email}, ${ip}) as ok`;
  if (!r.ok) return generic;
  const [m] = await sql`select 1 from public.members where lower(email) = ${email}`;
  if (!m) return generic;
  const [u] = await sql`select id from auth.users where lower(email) = ${email} and deleted_at is null`;
  if (!u) { const { error } = await admin.auth.admin.createUser({ email, email_confirm: true, password: randomSecret() }); if (error) throw new Error('criar: ' + error.message); }
  const origin = req.headers.get('origin') || '';
  const pub = createClient(SUPABASE_URL, ANON_KEY, opts);
  await pub.auth.resetPasswordForEmail(email, ORIGIN_OK.test(origin) ? { redirectTo: origin } : undefined);
  return generic;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== 'POST') return json(req, 405, { error: 'metodo' });
  let body: any = {};
  try { body = await req.json(); } catch { return json(req, 400, { error: 'json' }); }
  try {
    if (body.action === 'login') return await login(req, body);
    if (body.action === 'set_password') return await setPassword(req, body);
    if (body.action === 'request_reset') return await requestReset(req, body);
    return json(req, 400, { error: 'acao' });
  } catch (e) {
    console.error(e);
    return json(req, 500, { error: 'interno', message: 'Não foi possível agora. Tente de novo em instantes.' });
  }
});
