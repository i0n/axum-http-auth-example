CREATE TABLE accounts (
  email VARCHAR PRIMARY KEY UNIQUE NOT NULL, CHECK (email <> ''),
  password VARCHAR NOT NULL,
  active BOOL DEFAULT true
);
