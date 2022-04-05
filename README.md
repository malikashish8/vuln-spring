# vuln-spring

Intentionally Vulnerable Spring Application to test coverage of SAST tools.

## Vulnerabilities

Vulnerabilities are tagged with a comment with `// Issue` string. Searching for it in the whole code base should help find all vulnerabilities.

### List

* XSS - Reflected and Stored
* SQLi
* CSRF
* SSRF
* Hardcoded Secrets
* Sensitive Data Exposure - Logging of Sensitive data
* XXE
* Open Redirect
* Broken Access Control - JWT issues
* Insecure Deserialization

## Design

Mimic a banking app with SQLi DB for user details and an HTML interface written in Spring MVC.

## Run for PoC

### Docker

Simply run the following Docker Compose command after changing to code directory:

`docker-compose up`

This will run two containers. One for the Spring app and another for Maria DB. The app listens on [http://127.0.0.1:8082](http://127.0.0.1:8082) by default.

## Develop

VS Code dev containers are used to develop this app. The configuration in `.devcontainer` also runs the db server.

## ToDo

* Add Bootstrap CSS so the web pages look better
