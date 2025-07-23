import { jwt } from "hono/jwt"
import { Hono } from "hono"
import { cors } from "hono/cors"
import { csrf } from "hono/csrf"
import { drizzle } from "drizzle-orm/postgres-js"
import { and, eq, gte, sql } from "drizzle-orm"
import { readingsTable } from "./db/schema"
import { Env, Variables } from "./utils/types"
import * as auth from "./auth"

const app = new Hono<{ Bindings: Env, Variables: Variables }>()

app.use(cors({
  origin: ["http://localhost:5173", "https://flare.nguyenan-study.workers.dev"],
  credentials: true,
  allowHeaders: ["Content-Type", "Authorization"]
}))
app.use(csrf({
  origin: ["http://localhost:5173", "https://flare.nguyenan-study.workers.dev"]
}))
app.use("/readings", async (c, next) => {
  const jwtMiddleware = jwt({
    secret: c.env.JWT_SECRET
  })
  return jwtMiddleware(c, next)
})

app.get("/test", async (c) => {
  console.log("HYPERDRIVE:", c.env.HYPERDRIVE.connectionString)
  console.log("DATABASE_URL:", c.env.DATABASE_URL, " |  ENV:", process.env.DATABASE_URL)
  console.log("MQTT_CLUSTER_URL:", c.env.MQTT_CLUSTER_URL, " |  ENV:", process.env.MQTT_CLUSTER_URL)
  console.log("MQTT_USERNAME:", c.env.MQTT_USERNAME, " |  ENV:", process.env.MQTT_USERNAME)
  console.log("MQTT_PASSWORD:", c.env.MQTT_PASSWORD, " |  ENV:", process.env.MQTT_PASSWORD)

  return c.text("OK", 200)
})

app.post("/login", auth.login)
app.post("/logout", auth.logout)
app.post("/refresh", auth.refresh)
app.post("/signup", auth.signUp)

app.get("/me", auth.verifyRefresh)
app.get("/verify-user", auth.verifyUser)

app.get("/readings", async (c) => {
  const id = c.get("jwtPayload").id
  const db = drizzle(c.env.HYPERDRIVE.connectionString)
  
  try {
    const data = await db.select({
      temperature: readingsTable.temperature,
      humidity: readingsTable.humidity,
      room: readingsTable.room,
      created_at: readingsTable.created_at
    })
      .from(readingsTable)
      .where(and(
        eq(readingsTable.user_id, id),
        gte(readingsTable.created_at, sql`NOW() - INTERVAL '30 day'`)
      ))
    
    return c.json({ data })
  }
  catch (error) {
    console.error(error)
    return c.text("Unable to fetch readings", 500)
  }
})

export default app
