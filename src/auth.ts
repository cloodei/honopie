import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { Context } from "hono";
import { drizzle } from "drizzle-orm/bun-sql";
import { createHash } from "crypto";
import { sign, verify } from "hono/jwt";
import { PostgresError } from "postgres";
import { JwtTokenExpired } from "hono/utils/jwt/types";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { Env, Variables } from "./utils/types";
import { refreshTokensTable, usersTable } from "./db/schema";

export async function login(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const { username, password } = await c.req.json()
  if (!username || !password || typeof username !== "string" || typeof password !== "string")
    return c.text("User not found", 404)

  const now = Math.floor(Date.now() / 1000)

  const db = drizzle(c.env.HYPERDRIVE.connectionString)
  const [user] = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    password: usersTable.password
  }).from(usersTable).where(eq(usersTable.username, username))

  if (!user)
    return c.text("User not found", 404)

  const isPasswordValid = await bcrypt.compare(password, user.password)
  if (!isPasswordValid)
    return c.text("Invalid credentials", 400)

  const access_payload = {
    id: user.id,
    exp: now + c.env.JWT_EXPIRATION_NUM
  }
  const access_token = await sign(access_payload, c.env.JWT_SECRET)

  const refresh_payload = crypto.randomUUID()
  const refresh_hash = createHash("sha256").update(c.env.REFRESH_HASH_SECRET + refresh_payload).digest("hex")

  setCookie(c, "refresh_token", refresh_payload, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: c.env.REFRESH_EXPIRATION_NUM
  })

  db.insert(refreshTokensTable).values({
    user_id: user.id,
    token_hash: refresh_hash
  })

  return c.json({ access_token, user_id: user.id })
}

export async function logout(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const rftoken = getCookie(c, "refresh_token")
  if (!rftoken)
    return c.text("Invalid refresh token", 400)

  const db = drizzle(c.env.HYPERDRIVE.connectionString)
  db.delete(refreshTokensTable)
    .where(eq(
      refreshTokensTable.token_hash,
      createHash("sha256").update(c.env.REFRESH_HASH_SECRET + rftoken).digest("hex")
    ))

  deleteCookie(c, "refresh_token")
  return c.text("OK", 200)
}

export async function signUp(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const { username, password } = await c.req.json()
  if (!username || !password || typeof username !== "string" || typeof password !== "string")
    return c.text("User not found", 404)

  const now = Math.floor(Date.now() / 1000)
  const db = drizzle(c.env.HYPERDRIVE.connectionString)

  try {
    const [user] = await db.insert(usersTable)
      .values({
        username,
        password: await bcrypt.hash(password, 10)
      })
      .returning({ id: usersTable.id })

    const access_payload = {
      id: user.id,
      exp: now + c.env.JWT_EXPIRATION_NUM
    }
    const access_token = await sign(access_payload, c.env.JWT_SECRET)

    const refresh_payload = crypto.randomUUID()
    setCookie(c, "refresh_token", refresh_payload, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: c.env.REFRESH_EXPIRATION_NUM
    })    
    
    const refresh_hash = createHash("sha256").update(c.env.REFRESH_HASH_SECRET + refresh_payload).digest("hex")
    db.insert(refreshTokensTable).values({
      user_id: user.id,
      token_hash: refresh_hash
    })

    return c.json({ access_token, user_id: user.id }, 201)
  }
  catch (error) {
    console.error(error)
    
    if (error instanceof PostgresError && error.code === "23505")
      return c.text("User already exists", 409)
    
    return c.text("Unable to create user", 406)
  }
}

export async function refresh(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const rftoken = getCookie(c, "refresh_token")
  if (!rftoken)
    return c.text("Invalid refresh token", 400)

  const now = new Date()
  try {
    const db = drizzle(c.env.HYPERDRIVE.connectionString)
    const [payload] = await db.select({
      id: refreshTokensTable.id,
      user_id: refreshTokensTable.user_id,
      created_at: refreshTokensTable.created_at
    })
      .from(refreshTokensTable)
      .where(eq(
        refreshTokensTable.token_hash,
        createHash("sha256").update(c.env.REFRESH_HASH_SECRET + rftoken).digest("hex")
      ))

    if (!payload)
      return c.text("Invalid refresh token", 400)

    const access_payload = {
      id: payload.user_id,
      exp: Math.floor(now.getTime() / 1000) + c.env.JWT_EXPIRATION_NUM
    }
    const access_token = await sign(access_payload, c.env.JWT_SECRET)

    const refresh_payload = crypto.randomUUID()
    const refresh_hash = createHash("sha256").update(c.env.REFRESH_HASH_SECRET + refresh_payload).digest("hex")

    setCookie(c, "refresh_token", refresh_payload, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: c.env.REFRESH_EXPIRATION_NUM
    })

    db.update(refreshTokensTable)
      .set({
        token_hash: refresh_hash,
        created_at: now
      })
      .where(eq(refreshTokensTable.id, payload.id))

    return c.json({ access_token, user_id: payload.user_id })
  }
  catch (error) {
    console.error(error)
    return c.text("Invalid refresh token", 400)
  }
}

export async function verifyRefresh(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const token = c.req.header("Authorization")?.split(" ")
  if (!token || token.length !== 2 || token[0] !== "Bearer")
    return c.text("Invalid access token", 401)

  try {
    const payload = await verify(token[1], c.env.JWT_SECRET)
    return c.json({ user_id: payload.id })
  }
  catch (error) {
    console.error(error)
    if (!(error instanceof JwtTokenExpired))
      return c.text("Invalid access token", 401)

    return refresh(c)
  }
}

export async function verifyUser(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const token = c.req.header("Authorization")?.split(" ")
  if (!token || token.length !== 2 || token[0] !== "Bearer")
    return c.text("Invalid access token", 401)

  try {
    const payload = await verify(token[1], c.env.JWT_SECRET)
    return c.json({ user_id: payload.id })
  }
  catch (error) {
    console.error(error)
    return c.text("Invalid access token", 401)
  }
}
