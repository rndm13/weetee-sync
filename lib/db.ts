import { Pool } from "pg";

require('dotenv').config();
let db: Pool = 
  new Pool({
    user: process.env.PGSQL_USER,
    password: process.env.PGSQL_PASSWORD,
    host: process.env.PGSQL_HOST,
    port: parseInt(process.env.PGSQL_PORT as string),
    database: process.env.PGSQL_DATABASE,
    ssl: parseInt(process.env.PGSQL_SSL as string) == 1,
  });

export default db;
