import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { Context } from "hono";
import { drizzle } from "drizzle-orm/bun-sql";
import { sign, verify } from "hono/jwt";
import { getCookie, setCookie } from "hono/cookie";
import { Env, Variables } from "./utils/types";
import { refreshTokensTable, usersTable } from "./db/schema";

export async function login(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const db = drizzle(c.env.HYPERDRIVE.connectionString)

  const { username, password } = await c.req.json()
  if (!username || !password || typeof username !== "string" || typeof password !== "string")
    return c.text("User not found", 404)

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

  const now = Math.floor(Date.now() / 1000)

  const access_payload = {
    id: user.id,
    exp: now + c.env.JWT_EXPIRATION_NUM
  }
  const access_token = await sign(access_payload, c.env.JWT_SECRET)

  const refresh_token = crypto.randomUUID()
  setCookie(c, "refresh_token", refresh_token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: c.env.REFRESH_EXPIRATION_NUM
  })

  db.insert(refreshTokensTable).values({
    user_id: user.id,
    token_hash: bcrypt.hashSync(refresh_token, 10)
  })

  return c.json({ access_token, user_id: user.id })
}

export async function refresh(c: Context<{ Bindings: Env, Variables: Variables }>) {
  const rftoken = getCookie(c, "refresh_token")
  if (!rftoken)
    return c.text("Invalid refresh token", 400)

  try {
    const db = drizzle(c.env.HYPERDRIVE.connectionString)
    const [payload] = await db.select({
      id: refreshTokensTable.id,
      user_id: refreshTokensTable.user_id,
    }).from(refreshTokensTable).where(eq(refreshTokensTable.token_hash, rftoken))

    if (!payload)
      return c.text("Invalid refresh token", 400)

    const access_payload = {
      id: payload.user_id,
      exp: Math.floor(Date.now() / 1000) + c.env.JWT_EXPIRATION_NUM
    }

    const access_token = await sign(access_payload, c.env.JWT_SECRET)
    const refresh_token = crypto.randomUUID()
    setCookie(c, "refresh_token", refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: c.env.REFRESH_EXPIRATION_NUM
    })

    db.insert(refreshTokensTable).values({
      user_id: payload.user_id,
      token_hash: bcrypt.hashSync(refresh_token, 10)
    })

    return c.json({ access_token, user_id: payload.user_id })
  }
  catch (error) {
    console.error(error)
    return c.text("Invalid refresh token", 400)
  }
}

