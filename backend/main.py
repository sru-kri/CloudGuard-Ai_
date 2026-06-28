from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib
import jwt
import json
import os
from datetime import datetime, timedelta

app = FastAPI(title="CloudGuard AI Backend")

# --- CROSS-ORIGIN RESOURCE SHARING (CORS) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "super-secret-cloudguard-key"
ALGORITHM = "HS256"

# --- NEW: PERSISTENT FILE DATABASE SETTINGS ---
USER_DB_FILE = "users.json"
FAKE_FINDINGS_DB = []  # Stores processed security findings (Module 4)

def load_users() -> dict:
    """Loads registered users from the local JSON file so they survive reloads."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_users(users: dict):
    """Saves registered users securely to the local JSON file."""
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

# --- DATA MODELS (SCHEMAS) ---
class UserAuth(BaseModel):
    username: str
    password: str

# --- HELPER FUNCTIONS ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- MODULE 2 & 3: MOCK INFRASTRUCTURE DATA ---
def get_mock_data():
    return [
        {
            "id": "i-0abcd1234efgh5678",
            "type": "EC2 Instance",
            "name": "Production-Web-Server",
            "configuration": {"PortsOpen": "0.0.0.0/0", "Encrypted": False}
        },
        {
            "id": "arn:aws:s3:::company-financial-records-2026",
            "type": "S3 Bucket",
            "name": "company-financial-records-2026",
            "configuration": {"PublicAccess": True, "SSEAlgorithm": None}
        },
        {
            "id": "arn:aws:iam::123456789012:role/AdminExecutionRole",
            "type": "IAM Role",
            "name": "AdminExecutionRole",
            "configuration": {"AttachedPolicies": ["AdministratorAccess"], "MissingEncryption": True}
        }
    ]

# --- BACKEND BASE ROUTE ---
@app.get("/")
def home():
    return {"message": "CloudGuard AI Backend is Running!"}

# --- MODULE 1: AUTHENTICATION ENDPOINTS ---
@app.post("/signup")
def signup(user: UserAuth):
    users = load_users()
    if user.username in users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Username already exists!"
        )
    
    # Store user securely
    users[user.username] = {
        "username": user.username, 
        "password": hash_password(user.password)
    }
    save_users(users)
    return {"message": f"User {user.username} registered successfully!"}

@app.post("/login")
def login(user: UserAuth):
    users = load_users()
    db_user = users.get(user.username)
    if not db_user or db_user["password"] != hash_password(user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Incorrect username or password"
        )
    
    token = create_access_token(username=user.username)
    return {"access_token": token, "token_type": "bearer"}


# --- MODULE 4 & 6: RULE ENGINE WITH AI EXPLANATION GENERATION ---
def evaluate_security_rules(resource: dict) -> list:
    findings = []
    r_type = resource["type"]
    config = resource.get("configuration", {})
    r_name = resource["name"]
    r_id = resource["id"]

    # --- RULE 1: PUBLIC S3 BUCKET ---
    if r_type == "S3 Bucket" and config.get("PublicAccess") == True:
        ai_reason = (
            f"AI Root-Cause Analysis: The S3 bucket '{r_name}' has its ACL or Bucket Policy configurations "
            f"set with a public wildcard principal (*). This exposes your corporate storage layer directly "
            f"to automated internet crawlers, presenting a critical data-leakage vector for sensitive company records."
        )
        ai_cli = (
            f"aws s3api put-public-access-block \\\n"
            f"  --bucket {r_name} \\\n"
            f"  --public-access-block-configuration "
            f"\"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        )
        findings.append({
            "resource_id": r_id, "resource_type": "S3", "rule_name": "public-bucket",
            "severity": "CRITICAL", "description": ai_reason, "remediation": ai_cli
        })

    # --- RULE 2: OPEN SSH PORT ---
    if r_type == "EC2 Instance" and config.get("PortsOpen") == "0.0.0.0/0":
        ai_reason = (
            f"AI Root-Cause Analysis: Instance '{r_name}' ({r_id}) is attached to a Security Group "
            f"permitting inbound TCP traffic on Port 22 from the 0.0.0.0/0 CIDR block. This leaves the instance "
            f"permanently vulnerable to SSH brute-force password spraying and zero-day protocol exploits."
        )
        ai_cli = (
            f"aws ec2 revoke-security-group-ingress \\\n"
            f"  --group-id sg-example123 \\\n"
            f"  --protocol tcp \\\n"
            f"  --port 22 \\\n"
            f"  --cidr 0.0.0.0/0"
        )
        findings.append({
            "resource_id": r_id, "resource_type": "EC2", "rule_name": "open-ssh-port",
            "severity": "HIGH", "description": ai_reason, "remediation": ai_cli
        })

    # --- RULE 3: ADMINACCESS ROLES ---
    if r_type == "IAM Role" and "AdministratorAccess" in config.get("AttachedPolicies", []):
        ai_reason = (
            f"AI Root-Cause Analysis: The execution trust boundary for identity '{r_name}' utilizes the unmanaged "
            f"AWS AdministratorAccess policy. If these access keys or associated session profiles are ever compromised, "
            f"an attacker gains total, unhindered administrative control over your entire cloud infrastructure environment."
        )
        ai_cli = (
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {r_name} \\\n"
            f"  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
        findings.append({
            "resource_id": r_id, "resource_type": "IAM", "rule_name": "admin-access-role",
            "severity": "HIGH", "description": ai_reason, "remediation": ai_cli
        })

    # --- RULE 4: MISSING ENCRYPTION ---
    if config.get("Encrypted") == False or config.get("SSEAlgorithm") is None or config.get("MissingEncryption") == True:
        ai_reason = (
            f"AI Root-Cause Analysis: The asset ecosystem for '{r_name}' relies on unencrypted write states. "
            f"This fails compliance standards (such as SOC2 and ISO 27001) because data at rest is not cryptographically "
            f"isolated against physical hardware storage extraction vectors."
        )
        if r_type == "S3 Bucket":
            ai_cli = f"aws s3api put-bucket-encryption --bucket {r_name} --server-side-encryption-configuration '{{ \"Rules\": [{{ \"ApplyServerSideEncryptionByDefault\": {{ \"SSEAlgorithm\": \"AES256\" }} }}] }}'"
        elif r_type == "EC2 Instance":
            ai_cli = f"aws ec2 modify-ebs-encryption-by-default --encrypted"
        else:
            ai_cli = f"aws kms create-key --description 'Default Compliance Key for {r_name}'"

        findings.append({
            "resource_id": r_id, "resource_type": r_type.split()[0], "rule_name": "missing-encryption",
            "severity": "MEDIUM", "description": ai_reason, "remediation": ai_cli
        })

    return findings


@app.post("/api/v1/compliance/scan")
def run_compliance_scan():
    global FAKE_FINDINGS_DB
    resources = get_mock_data()
    FAKE_FINDINGS_DB = []
    
    for resource in resources:
        violations = evaluate_security_rules(resource)
        FAKE_FINDINGS_DB.extend(violations)
        
    return {
        "status": "success",
        "total_findings_logged": len(FAKE_FINDINGS_DB)
    }


@app.get("/api/v1/findings")
def get_findings():
    return FAKE_FINDINGS_DB


# --- SERVER INITIATION ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)