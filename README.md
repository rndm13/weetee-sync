# File sync API

An API that allows for user auth and file saving.

## Installation

Install this repo on your computer and all dependencies.

```sh
$ git clone https://github.com/rndm13/weetee-sync.git
$ cd weetee-sync
$ npm i
$ npx tsx watch api/
```

Copy `.env.example` and edit it.

```sh 
$ cp .env.example .env
$ vim .env
```

## Endpoints
### GET /login

Login as user.

HTTP Query Params:
- name: string - user's name.
- password: string - user's password.
- remember_me: boolean - sets session token expiry date to a month instead of a single day.

Returns session token.

### GET /register

Register a new user.

HTTP Query Params:
- name: string - user's name.
- password: string - user's password.
- remember_me: boolean - sets session token expiry date to a month instead of a single day.

Returns new user's session token.

### GET /logout

Logs out of session. Also expires session token.

HTTP Query Params:
- session_token: string - user's session token,

Returns nothing.

### GET /file-list

Get a list of files.

HTTP Query Params:
- session_token: string - user's session token,

Returns a list of user's files in JSON format.

Example:
```json
[
    {"name": "hello_world.txt"},
    {"name": "README.md"},
]
```

### GET /file

Request contents of a file.

HTTP Query Params:
- session_token: string - user's session token,
- file_name: string - name of requested file,

Returns contents of a file as octet-stream (max 2MB).

### POST /file

Create a new file or set its contents.

HTTP Query Params:
- session_token: string - user's session token,
- file_name: string - name of file,

HTTP Body application/octet-stream must be file contents.

Returns nothing.

### PATCH /file

Rename a file.

HTTP Query Params:
- session_token: string - user's session token,
- file_name: string - current name of file,
- file_name: string - new name of file,

Returns nothing.

### DELETE /file

Delete a file.

HTTP Query Params:
- session_token: string - user's session token,
- file_name: string - name of file to delete,

Returns nothing.
