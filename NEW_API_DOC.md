### Endpoints

#### 1. Health Check
```
GET /
```
Simple health check endpoint that returns "OK" if the server is running.

**Response**
- Status: 200 OK
- Body: "OK"

#### 2. Health Check 1
```
GET /health1
```
Health check endpoint that returns a success code.

**Response**
- Status: 200 OK
- Body: 
```json
{
    "code": 200
}
```

#### 3. Health Check 2
```
GET /health2
```
Alternative health check endpoint that returns a success code.

**Response**
- Status: 200 OK
- Body: 
```json
{
    "code": 200
}
```

#### 4. File Conversion
```
POST /upload
```
Converts supported document files (doc, docx, hwp) to PDF format.

**Request**
- Content-Type: multipart/form-data
- Headers:
  - `session`: Required. User session token for authentication
  - `health-check-admin`: Optional. Use value 'donue' for admin access

**Parameters**
- `file`: The document file to be converted (doc, docx, or hwp)
- `endpoint`: Required. The endpoint URL for user authentication

**Response**
- Success:
  - Status: 200 OK
  - Content: Converted PDF file (downloadable)
- Error Cases:
  - 400 Bad Request: If file is encrypted ("ENCRYPT" message)
  - 400 Bad Request: For other conversion errors (empty JSON response)
  - Unauthorized: If authentication fails

**Example Request**
```http
POST /upload
Content-Type: multipart/form-data
session: user-session-token

--boundary
Content-Disposition: form-data; name="file"; filename="document.docx"
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document

[File Content]
--boundary
Content-Disposition: form-data; name="endpoint"

https://api.example.com
--boundary--
```