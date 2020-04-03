# vuln-spring
Intentionally Vulnerable Spring Application to test coverage of SAST tools.

## Vulnerabilities
Vulnerabilities are tagged with a comment with `Issue` string. Searching for it in the whole code base should help find all vulnerabilities. 

### Done
* XSS - Reflected and Stored
* SQLi
* CSRF
* SSRF
* Hardcoded Secrets
* Sensitive Data Exposure - Logging of Sensitive data

### ToDo
* Broken Access Control - JWT issues
* Insecure Deserialization
* XXE
* Open Redirect

## Design

Mimic a banking app with SQLi DB for user details and an HTML interface written in Spring MVC.

## Run

Setup the database as follows and run the application as Spring:

`./mvnw spring-boot:run`

It listens on [http://127.0.0.1:8082](http://127.0.0.1:8082) by default.

### DB on Docker
`docker run --rm -p 3306:3306 --name mariadb-vuln-spring -e MYSQL_ROOT_PASSWORD=Password mariadb`

Run `init.sql` on this DataBase to initialize it with some data.
