CREATE TABLE "Users"
(
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  name TEXT NOT NULL,
  surname TEXT NOT NULL,
  admin BOOL NOT NULL
);

