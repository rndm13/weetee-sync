import express from "express";

import db from "../lib/db";

var bodyParser = require("body-parser");
var bcrypt = require("bcryptjs");
import {
  user_lookup,
  generate_session_token,
  UserLookupError,
  UserData,
} from "../lib/user";

const app = express();
app.use(bodyParser.raw({ type: "application/octet-stream", limit: "2mb" }));

app.get("/", (req, res) => {
  res.send("You are at root!");
});

app.get("/init-db", async (_, res) => {
  await db.query(`
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            name varchar(50) UNIQUE NOT NULL,
            password_hash varchar(255) NOT NULL,
            session_token varchar(255),
            session_timeout date
        );

        CREATE TABLE IF NOT EXISTS files(
            id SERIAL PRIMARY KEY,
            owner_id INT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            name varchar(50) NOT NULL,
            UNIQUE(owner_id, name),
            data bytea NOT NULL
        );
    `);
  res.sendStatus(200);
});

interface LoginQuery {
  name: string;
  password: string;
  remember_me: boolean;
}

app.get("/login", async (req: express.Request<{}, {}, {}, LoginQuery>, res) => {
  var lookup = await db.query(
    "SELECT id, password_hash FROM users WHERE name = $1",
    [req.query.name],
  );

  if (lookup.rows.length <= 0) {
    res.sendStatus(404);
    return;
  }

  if (!bcrypt.compareSync(req.query.password, lookup.rows[0].password_hash)) {
    res.sendStatus(403);
    return;
  }

  var today = new Date();
  var expiry_date = new Date(new Date().setDate(today.getDate() + 1));
  if (req.query.remember_me) {
    expiry_date = new Date(new Date().setDate(today.getDate() + 30));
  }

  var session_token = await generate_session_token();

  db.query(
    `
    UPDATE users SET
      session_token = $2,
      session_timeout = $3
    WHERE id = $1
  `,
    [lookup.rows[0].id, session_token, expiry_date],
  );

  res.send(session_token);
});

interface LogoutQuery {
  session_token: string;
}

app.get(
  "/logout",
  async (req: express.Request<{}, {}, {}, LogoutQuery>, res) => {
    db.query(
      `
      UPDATE users SET
          session_token = NULL,
          session_timeout = NULL
      WHERE session_token = $1`,
      [req.query.session_token],
    );
    res.sendStatus(200);
  },
);

interface RegisterQuery {
  name: string;
  password: string;
  remember_me: boolean;
}

app.get(
  "/register",
  async (req: express.Request<{}, {}, {}, RegisterQuery>, res) => {
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(req.query.password, salt);
    var session_token = await generate_session_token();

    var today = new Date();
    var expiry_date = new Date(new Date().setDate(today.getDate() + 30));

    await db.query(
      "INSERT INTO users(name, password_hash, session_token, session_timeout) VALUES ($1, $2, $3, $4)",
      [req.query.name, hash, session_token, expiry_date],
    );

    res.send(session_token);
  },
);

interface FileQuery {
  session_token: string;
  file_name: string;
}

app.post("/file", async (req: express.Request<{}, {}, {}, FileQuery>, res) => {
  var user = await user_lookup(req.query.session_token);
  if (
    user == UserLookupError.NotFound ||
    user == UserLookupError.ExpiredSession
  ) {
    res.sendStatus(403);
    return;
  }

  if (req.query.file_name == null) {
    res.status(400);
    return;
  }

  await db.query(
    `
    INSERT INTO files(owner_id, name, data)
    VALUES($1, $2, $3)
    ON CONFLICT (owner_id, name) 
    DO UPDATE SET 
    data = $3;`,
    [user.id, req.query.file_name, req.body],
  );

  res.sendStatus(200);
});

app.get("/file", async (req: express.Request<{}, {}, {}, FileQuery>, res) => {
  var user = await user_lookup(req.query.session_token);
  if (
    user == UserLookupError.NotFound ||
    user == UserLookupError.ExpiredSession
  ) {
    res.sendStatus(403);
    return;
  }

  if (req.query.file_name == null) {
    res.status(400);
    return;
  }

  var result = await db.query(
    "SELECT data FROM files WHERE owner_id = $1 AND name = $2",
    [user.id, req.query.file_name],
  );

  if (result.rows.length <= 0) {
    res.status(404);
    return;
  }

  res.send(result.rows[0].data);
});

interface FileListQuery {
  session_token: string;
}

app.get("/file-list", async (req: express.Request<{}, {}, {}, FileListQuery>, res) => {
  var user = await user_lookup(req.query.session_token);
  if (
    user == UserLookupError.NotFound ||
    user == UserLookupError.ExpiredSession
  ) {
    res.sendStatus(403);
    return;
  }

  var result = await db.query(
    "SELECT name FROM files WHERE owner_id = $1",
    [user.id],
  );

  if (result.rows.length <= 0) {
    res.status(404);
    return;
  }

  res.contentType("application/json").send(result.rows);
});

app.listen(3000, () => console.log("Server ready at: http://localhost:3000"));
