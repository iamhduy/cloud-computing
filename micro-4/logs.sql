DROP TABLE IF EXISTS log;

CREATE TABLE log
    (id INTEGER primary key AUTOINCREMENT,
        username TEXT,
        event TEXT,
        filename TEXT
);