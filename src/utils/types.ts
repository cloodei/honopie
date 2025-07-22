import { Hyperdrive } from "@cloudflare/workers-types"
import { JwtVariables } from "hono/jwt"

type JwtPayload = {
  id: number
}
type Env = {
  HYPERDRIVE: Hyperdrive

  MQTT_CLUSTER_URL: string
  MQTT_USERNAME: string
  MQTT_PASSWORD: string

  JWT_SECRET: string
  JWT_EXPIRATION_NUM: number
  REFRESH_EXPIRATION_NUM: number
  REFRESH_HASH_SECRET: string
}
type Variables = JwtVariables<JwtPayload>

export { Env, Variables, JwtPayload }
