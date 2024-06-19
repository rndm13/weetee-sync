import db from "./db";
import express from "express";

import {randomBytes} from "crypto";

export async function generate_session_token(): Promise<string> {
  var session_token = randomBytes(16).toString("base64");

  var result = await db.query(
      `
    SELECT id FROM users WHERE session_token = $1`,
      [ session_token ],
  );

  if (result.rows.length > 0) {
    return generate_session_token();
  }

  return session_token;
}

export interface UserData {
  id: number;
  name: string;
  password_hash: string;
  session_token: string;
  session_timeout: Date;
}

export enum UserLookupError {
  NotFound,
  ExpiredSession,
}

export function get_session_token(request: express.Request<{}, {}, {}, any>) {
    if (request.query.session_token != null) {
        return request.query.session_token;
    }
    return request.cookies["session_token"];
}

export async function user_lookup(
    session_token: string,
    ): Promise<UserData|UserLookupError> {
  var result = await db.query(
      `
    SELECT * FROM users WHERE session_token = $1`,
      [ session_token ],
  );

  if (result.rows.length <= 0) {
    return UserLookupError.NotFound;
  }
  if (result.rows[0].session_timeout < Date()) {
    return UserLookupError.ExpiredSession;
  }

  return result.rows[0];
}
