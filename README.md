# Spring Security & Containerization
## Advanced Coding Assignment-9
## Store Management System API

### Problem Statement
You have been provided with a RESTful web service for a **Store Management System** using Spring Boot. The API allow users to manage products, including adding, updating, deleting, and retrieving products. The system store the product data in a Postgres database.

You are tasked with implementing **Spring Security** for API security using Basic Authentication and JSON Web Tokens (JWT) for secure communication, as well as **Dockerizing** the application for container-based deployment. Basic Authentication will be used for the initial login, which provides credentials (username and password) to authenticate the user. Once authenticated, JWT tokens will be issued to the client for subsequent requests to access protected resources.

### Objective
To implement a Spring Boot application with the following security features:

1. **Basic Authentication:** Use Spring Security to implement Basic Authentication to secure the application’s login mechanism, requiring the user to provide their credentials.
2. **JWT Authentication:** After successful login, implement JWT-based token authentication for subsequent requests, where the server issues a JWT token upon successful login and validates the token for accessing protected resources.
3. **Containerization:** Use Docker to containerize the Spring Boot application, ensuring that it can be run consistently across different environments.

### Steps to Follow
1. This GitHub repository will be accessible to you once you accept the Assignment.
2. You have to work directly in this GitHub repository. It is like your own copy of the original repository.

3. The folder structure is as given below: (showing major files only)
   ```
   root
   ├── pom.xml
   └── src/main
       ├── java/com/mystore/app
       |   ├── config
       |   |   ├── MyGlobalExceptionHandler.java
       |   |   └── OASConfig.java
       |   ├── entity
       |   |   └── Product.java
       |   ├── repositories
       |   |   └── ProductRepository.java
       |   ├── rest
       |   |   └── ProductController.java
       |   ├── service
       |   |   └── ProductService.java
       |   └── AppApplication.java
       └── resources
           ├── static
           |   └── index.html
           └── application.properties
   ```

4. Review the code/comments present in above files to understand the structure.
5. Implement the Spring Security and Containerize the application.
7. To work on the files, you can clone this GitHub repository onto your system and then open it with an IDE like IntelliJ, or Eclipse.
8. Once done, push your changes from your system to this remote GitHub repository.

### Starter Code Files:
Starter code for below functionalities have already provided:
1. **Spring Boot application:**
   - Use Spring Boot to set up the application.
   - Use `Spring Web` dependency to create the RESTful APIs.
   - A Postgres database is already configured to store products' data. The provided `application.properties` file contains the related details like - database location, database name, username, and password.

2. **Product Entity:**
   A `Product` class is already provided with the following fields:
   - `id` (Integer, Unique Identifier for the Product)
   - `name` (String, Not Null)
   - `category` (String, Not Null, e.g., "Electronics", "Clothing", etc.)
   - `price` (Double, Not Null, must be a positive value)
   - `stockQuantity` (Integer, Not Null, must be a non-negative value)

3. **REST Endpoints:** Implementation provided for the following REST endpoints for managing the products:
   - **Create a new product:** `POST /products`
     - Request Body: JSON object with fields `name`, `category`, `price` and `stockQuantity`.
     - Response: JSON object with the newly created product details, including the generated `id`.
   - **Get all products:** `GET /products`
     - Response: A list of all products in JSON format.
   - **Get a product by ID:** `GET /products/{id}`
     - Response: A JSON object of a single product, or `404 Not Found` if the product doesn't exist.
   - **Update product details:** `PUT /products/{id}`
     - Request Body: JSON object with updated fields `name`, `category`, `price`, `stockQuantity`.
     - Response: The updated product details, or `404 Not Found` if the product doesn't exist.
   - **Delete a product:** `DELETE /products/{id}`
     - Response: `204 No Content` if the product is deleted successfully, or `404 Not Found` if the product doesn't exist.


## Requirements:
1. **Basic Authentication Implementation**
   
   - Allow users to authenticate using a username and password through HTTP Basic Authentication.
   - Create and store users in the Database.
      - Create an entity `User` and give a table name other than `user` or `users`. For example, you can give name in this format `yourname_users`
   - Store encrypted password.
   - Make all the API endpoints secure except for the one with which a user is added.

2. **JWT Implementation:**
   - After a successful authentication, generate a JWT token containing user information and an expiration time.
   - Include the JWT token in the response and require the token to be included in the `Authorization` header of each subsequent request to access protected resources.
   - Implement token validation logic for every protected endpoint.

3. **Dockerization**

   - Create a Dockerfile for the Spring Boot application.
   - Build and run the Spring Boot application inside a Docker container on your system, ensuring that the application is easily deployable across multiple environments.


## Submission Requirements:
Implement the required tasks for the provided Spring Boot application. You can use Postman or cURL commands to test your API endpoints. You can also check the tables and their content present on the database(provided to you) using this [link](https://yrajm1997-accessing-db.hf.space).

Add the required execution screenshots, such as docker commands execution, in the `SubmissionImages` folder.

After completing the assignment and developing the solution code in your system, commit and push the changes to this repository. 
  - Stage your changes and commit the files:
    ```
    git add .
    git commit -m "Completed the assignment"
    ```
  - Push your changes to the GitHub repository:
    ```
    git push
    ```

## Grading Criteria:
- To implement Basic authentication correctly [5 Marks]
- To implement JWT based authentication correctly [3 Marks]
- To dockerize the application correctly [2 Marks]

Good luck, and happy coding!
