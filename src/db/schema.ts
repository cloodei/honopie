import { index, pgTable, real, serial, timestamp, varchar } from "drizzle-orm/pg-core"

export const usersTable = pgTable("users", {
  id: serial("id").primaryKey(),
  username: varchar({ length: 128 }).unique().notNull(),
  password: varchar({ length: 255 }).notNull(),
  created_at: timestamp({ withTimezone: true, mode: "date" }).defaultNow().notNull(),
  updated_at: timestamp({ withTimezone: true, mode: "date" }).defaultNow().notNull().$onUpdateFn(() => new Date())
})

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: serial("id").primaryKey(),
  user_id: serial("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  token_hash: varchar({ length: 255 }).notNull().unique(),
  created_at: timestamp({ withTimezone: true, mode: "date" }).defaultNow().notNull()
}, table => [
  index("user_index").on(table.user_id),
])

export const readingsTable = pgTable("readings", {
  id: serial("id").primaryKey(),
  user_id: serial("user_id").notNull().references(() => usersTable.id),
  room: varchar({ length: 128 }).notNull(),
  temperature: real().notNull(),
  humidity: real().notNull(),
  created_at: timestamp({ withTimezone: true, mode: "date" }).defaultNow().notNull()
}, table => [
  index("room_idx").on(table.room),
  index("user_idx").on(table.user_id)
])
