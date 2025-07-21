import { Hyperdrive } from "@cloudflare/workers-types"
import { JwtVariables } from "hono/jwt"

type JwtPayload = {
  id: string
  username: string
}
type Env = {
  HYPERDRIVE: Hyperdrive
}
type Variables = JwtVariables<JwtPayload>

export { Env, Variables, JwtPayload }
