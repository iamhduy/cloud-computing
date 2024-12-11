DROP TABLE IF EXISTS user;

CREATE TABLE user
    (id INTEGER primary key AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        username TEXT(20) UNIQUE,
        email TEXT(50) UNIQUE,
        group_name TEXT,
        password TEXT,
        salt TEXT
     );