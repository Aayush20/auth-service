# 🔐 Auth Service

The **Auth Service** is a core Spring Boot microservice responsible for user authentication, authorization, token management, and role/scope-based access control in a production-grade e-commerce system.

---

## 🚀 Features

- ✅ OAuth2 Authorization Server (Access + Refresh Tokens)
- ✅ Secure Login with JWT Token Generation
- ✅ Email Verification on Signup
- ✅ Forgot & Reset Password via Secure Tokens
- ✅ Role-Based Access Control (Admin, Customer, Internal)
- ✅ Scope-Based Microservice Authorization
- ✅ Token Introspection API (`/auth/validate`)
- ✅ Refresh Token Rotation & Blacklisting
- ✅ Redis-backed Blacklist for Logout
- ✅ Swagger OpenAPI 3.0 Documentation
- ✅ Dockerized with GitHub Actions CI
- ✅ MDC Logging (userId, requestId)

---

## 🧰 Tech Stack

- Java 21
- Spring Boot 3.x
- Spring Security + OAuth2 Auth Server
- Spring Data JPA + MySQL
- JWT (Nimbus)
- Redis
- SendGrid Email
- Docker
- GitHub Actions CI

---

## 📂 Folder Structure

```
auth-service/
├── configs/
├── controllers/
├── dtos/
├── models/
├── repositories/
├── security/
├── services/
├── utils/
├── resources/
│   └── application.properties
├── Dockerfile
├── pom.xml
└── README.md
```

---

## 📦 Running the Service

### 1. Prerequisites

- Java 21, Maven
- MySQL & Redis running
- Eureka Server if using service discovery

### 2. Run Locally

```bash
./mvnw clean install
java -jar target/auth-service-0.0.1-SNAPSHOT.jar
```

### 3. Swagger

- [http://localhost:8081/swagger-ui.html](http://localhost:8081/swagger-ui.html)

---

## 📬 Email Support

- SendGrid used to send:
    - Verification links
    - Password reset links
- Configurable from `application.properties`

---

## 🔐 Security

- JWT access token verification
- Redis token blacklist on logout
- Role (`ROLE_ADMIN`, etc.) and Scope (`SCOPE_internal`, etc.)
- `/auth/validate` used by other services

---

## 📈 Observability

- Prometheus-compatible metrics
- Structured logs with MDC

---

## 🐳 Docker

```bash
docker build -t auth-service .
docker run -p 8081:8081 auth-service
```

---

## 🚀 CI/CD

- GitHub Actions Maven build + test + Docker build

---

## 🧠 Future Enhancements

| Feature                              | Status   |
|--------------------------------------|----------|
| Google/GitHub SSO                    | ⏳ Pending |
| Account Locking after failed attempts| ⏳ Pending |
| Rate limiting for login/reset APIs   | ⏳ Pending |
| Swagger grouping + example schemas   | ⏳ Pending |
| Deployment automation (ECR/GCP/AWS)  | ⏳ Pending |
| ELK/Zipkin/Grafana integration       | ⏳ Pending |
| DB migration with Flyway             | ⏳ Pending |