import { Hono } from "hono"
import { cors } from "hono/cors"
import { csrf } from "hono/csrf"
import { jwt, JwtVariables } from "hono/jwt"
import { Hyperdrive } from "@cloudflare/workers-types"

type Env = {
  HYPERDRIVE: Hyperdrive
}
type Variables = JwtVariables
const app = new Hono<{ Bindings: Env, Variables: Variables }>()

app.use(cors({
  origin: ["http://localhost:5173", "https://flare.nguyenan-study.workers.dev"],
  credentials: true,
  allowHeaders: ["Content-Type", "Authorization"]
}))
app.use(csrf({
  origin: ["http://localhost:5173", "https://flare.nguyenan-study.workers.dev"]
}))
app.use(jwt({
  secret: "secret",
  cookie: {
    key: "secret",
    
  }
}))

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

export default app
