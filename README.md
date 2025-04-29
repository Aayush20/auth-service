# Auth Service

The **Auth Service** is a Spring Boot-based application providing secure authentication and authorization functionalities for a microservices ecosystem. It handles user registration, token issuance, validation, secure user management, and more. It supports easy integration with other microservices (e.g., Order Service, Product Catalog Service).

---

## 🚀 Features

- User Registration & Default Role Assignment (CUSTOMER)
- JWT-Based Authentication (Access Tokens)
- Secure Endpoints with Role-Based Access Control (RBAC)
- Email Verification using Token
- Forgot Password and Reset Password using Token
- Dockerized Deployment
- Swagger/OpenAPI Documentation
- Eureka Client Support (Optional for Service Discovery)
- Event Publishing (Future Integration: Kafka / RabbitMQ)

---

## 🛠️ Technology Stack

- Java 21
- Spring Boot 3.x
- Spring Security & OAuth2 Authorization Server
- Spring Data JPA + MySQL
- JWT (Nimbus JOSE JWT)
- Docker
- GitHub Actions (CI)
- Swagger/OpenAPI 3

---

## 🏗️ Project Structure

auth-service/ ├── configs/ ├── controllers/ ├── dtos/ ├── models/ ├── repositories/ ├── security/ ├── services/ ├── utils/ ├── resources/ │ ├── application-dev.properties │ ├── application-prod.properties │ ├── application.yml ├── Dockerfile ├── pom.xml └── README.md


---

## 📚 Getting Started

### Prerequisites

- Java 21
- Maven 3.8+
- MySQL running locally (update DB config)
- Optional: Eureka Server for service registration

---

### Run Locally

```bash
# Clone the repository
git clone https://github.com/your-username/auth-service.git

# Navigate to project
cd auth-service

# Build the project
./mvnw clean package

# Run the application
java -jar target/auth-service-0.0.1-SNAPSHOT.jar
```

--- 

### API Documentation (Swagger UI)

Once the application is running:

- Visit: http://localhost:8081/swagger-ui.html

- Or: http://localhost:8081/swagger-ui/index.html

✅ All available endpoints will be auto-documented there!

---

### 🐳 Docker Deployment

Build Docker Image

```bash
docker build -t auth-service .
```

Run Docker Container

```bash
docker run -p 8081:8081 auth-service
```

---

### 🔥 Future Enhancements

- Real Email Service Integration (SendGrid)

- Refresh Token Implementation

- OAuth2 Single Sign On (Google, GitHub)

- SonarQube Code Quality Integration

- Swagger Endpoint Grouping , Detailed Descriptions and response model schemas.

- Account Locking after multiple failed login attempts

- Password Reset Rate Limiting

- Deploy to AWS EC2 using Docker Compose

- Centralized Logging (ELK Stack)

---

### ⚙️ GitHub Actions CI/CD

Every push or pull request to main triggers a Maven build automatically using GitHub Actions.

- Workflow file: .github/workflows/maven.yml

- Ensures code builds cleanly with every commit!

---

⭐ Thanks for Visiting! ⭐

