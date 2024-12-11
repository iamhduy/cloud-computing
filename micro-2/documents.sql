DROP TABLE IF EXISTS document;
DROP TABLE IF EXISTS group_doc;

CREATE TABLE document
    (id INTEGER primary key AUTOINCREMENT,
        filename TEXT,
        body TEXT,
        owner TEXT
     );

CREATE TABLE group_doc
    (id INTEGER primary key AUTOINCREMENT,
        doc_name TEXT,
        name TEXT,
        FOREIGN KEY (doc_name) REFERENCES document(filename)
     );