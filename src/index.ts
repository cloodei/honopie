import { jwt } from "hono/jwt"
import { Hono } from "hono"
import { cors } from "hono/cors"
import { csrf } from "hono/csrf"
import { Env, Variables } from "./utils/types"
import { login } from "./auth"

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

app.post('/login', login)

app.get('/readings', (c) => {
  return c.json({ message: 'Hello Hono!' })
})

export default app
