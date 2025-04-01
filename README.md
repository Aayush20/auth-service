# Auth Service

The **Auth Service** is a Spring Boot-based application that provides secure authentication and authorization for your microservices' ecosystem. It handles user registration, token issuance, validation, and exposes secure endpoints for managing user profiles and addresses. It also registers with Eureka for service discovery and is designed for easy integration with other microservices (e.g., Order Service and ProdCat Service).

## Features

- **User Registration & Default Role Assignment:**  
  New user signups are registered with a default role (e.g., `CUSTOMER`). The password is encoded (using BCrypt) and role management is controlled through externalized RBAC properties.

- **JWT-Based Authentication:**  
  The service generates and validates JSON Web Tokens. RSA keys are generated at startup (for development only) and used for signing and validating tokens. (In production, persist keys to ensure token continuity.)

- **Secure Endpoints:**
    - Public endpoints: `/auth/signup`, `/auth/validate`
    - Protected endpoints: `/api/profile`, `/api/address`
    - Administrative endpoints (secured via method-level security): e.g., updating user roles via `/api/admin/users/{userId}/role`.

- **Eureka Client Integration:**  
  The service is configured to register with a Eureka Server to allow for dynamic service discovery in a microservices architecture, while still supporting testing as a standalone service on its own port.

- **Event Publishing (Future-Proofing):**  
  When a user signs up, a `UserRegisteredEvent` is published. Although no message broker is set up currently, this paves the way for future asynchronous workflows (e.g., sending welcome emails or updating downstream caches).

## Technology Stack

- **Spring Boot 3.x**
- **Spring Security & OAuth2 Authorization Server**
- **Spring Data JPA & MySQL**
- **Eureka Client (Netflix OSS)**
- **JWT (io.jsonwebtoken)**
- **Maven for Build & Dependency Management**

## Getting Started

### Prerequisites

- Java 11 or later (Java 21 is configured in this project)
- Maven
- A running MySQL database (update the JDBC URL, username, and password in `application.properties`)
- (Optional) A running Eureka Server at `http://localhost:8761/eureka`

### Setup

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/your-repo/AuthService.git
    cd AuthService
    ```

2. **Configure your application properties:**  
   Ensure the settings in `src/main/resources/application.properties` match your environment. For testing in isolation, the Eureka client settings won’t affect you.

3. **Build the Project:**

    ```bash
    mvn clean install
    ```

4. **Run the Application:**

    ```bash
    mvn spring-boot:run
    ```

   The application will start on port **8081** (as configured) and can be tested via Postman.

### Endpoints

- **User Registration:**  
  `POST /auth/signup`  
  Payload:
  ```json
  {
      "name": "Aayush",
      "email": "aayush@example.com",
      "password": "yourpassword",
      "phoneNumber": "1234567890"
  }

Token Validation: POST /auth/validate Include the JWT in the Authorization header as Bearer <token>.

User Profile: GET /api/profile Returns the current user's profile along with their addresses.

Address Management: Endpoints under /api/address support GET, POST, PUT, and DELETE to manage addresses.

Admin Role Updates: PUT /api/admin/users/{userId}/role Secured so that only users with the ADMIN role can update a user’s role.
