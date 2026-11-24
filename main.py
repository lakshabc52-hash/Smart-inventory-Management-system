import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError, DuplicateKeyError

load_dotenv()
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "smart_inventory")
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "local-development-secret-change-me")
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "12"))
client = MongoClient(MONGODB_URL, serverSelectionTimeoutMS=3000)
database = client[DATABASE_NAME]
products_collection = database["products"]
warehouses_collection = database["warehouses"]
suppliers_collection = database["suppliers"]
movements_collection = database["stock_movements"]
users_collection = database["users"]
bearer = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    client.admin.command("ping")
    products_collection.create_index("sku", unique=True)
    users_collection.create_index("email", unique=True)
    yield
    client.close()

app = FastAPI(title="Smart Inventory API", description="Inventory, warehouse, supplier and user-role management API.", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?", allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)

class Product(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    sku: str = Field(min_length=1, max_length=50)
    category: str = Field(default="General", max_length=100)
    quantity: int = Field(default=0, ge=0)
    price: float = Field(default=0, ge=0)
    min_stock: int = Field(default=5, ge=0)

class StockUpdate(BaseModel):
    quantity: int = Field(ge=0)

class Warehouse(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    location: str = Field(default="", max_length=200)
    capacity: int = Field(default=0, ge=0)
    status: str = Field(default="Active", max_length=30)

class Supplier(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    contact: str = Field(default="", max_length=100)
    email: str = Field(default="", max_length=150)
    address: str = Field(default="", max_length=250)

def serialize_document(item):
    if item is None:
        return None
    item["id"] = str(item.pop("_id"))
    item.pop("password_hash", None)
    item.pop("password_salt", None)
    return item

def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return base64.b64encode(salt).decode(), base64.b64encode(hashed).decode()

def verify_password(password: str, salt_text: str, expected_hash: str):
    try:
        salt = base64.b64decode(salt_text)
        _, actual = hash_password(password, salt)
        return hmac.compare_digest(actual, expected_hash)
    except (ValueError, TypeError):
        return False

def make_token(user):
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user["_id"]), "exp": int((now + timedelta(hours=TOKEN_HOURS)).timestamp())}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signature = hmac.new(TOKEN_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
    signed = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{encoded}.{signed}"

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Please log in to continue")
    try:
        encoded, signature = credentials.credentials.split(".", 1)
        expected = base64.urlsafe_b64encode(hmac.new(TOKEN_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if int(payload["exp"]) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("expired token")
        user = users_collection.find_one({"_id": ObjectId(payload["sub"]), "active": True})
        if not user:
            raise ValueError("user unavailable")
        return {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user["role"]}
    except (ValueError, KeyError, TypeError, InvalidId, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please log in again")

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Admin permission required")
    return user

def record_movement(product_id, product_name, movement_type, quantity, user):
    if quantity <= 0:
        return
    movements_collection.insert_one({"product_id": str(product_id), "product": product_name, "type": movement_type, "quantity": int(quantity), "date": datetime.now(timezone.utc).astimezone().isoformat(), "performed_by": user["name"], "performed_by_role": user["role"]})

@app.get("/")
def home():
    return {"message": "Smart Inventory API is running!", "docs": "/docs"}

@app.get("/health")
def health_check():
    try:
        client.admin.command("ping")
        return {"status": "healthy", "mongodb": "connected", "database": DATABASE_NAME}
    except PyMongoError:
        raise HTTPException(status_code=503, detail="MongoDB is not available")

@app.post("/auth/signup", status_code=201)
def signup(request: SignupRequest):
    email = request.email.strip().lower()
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    if users_collection.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    salt, password_hash = hash_password(request.password)
    role = "Admin" if users_collection.count_documents({}) == 0 else "Staff"
    document = {"name": request.name.strip(), "email": email, "password_salt": salt, "password_hash": password_hash, "role": role, "active": True, "created_at": datetime.now(timezone.utc).isoformat()}
    try:
        result = users_collection.insert_one(document)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    document["_id"] = result.inserted_id
    return {"access_token": make_token(document), "token_type": "bearer", "user": serialize_document(document)}

@app.post("/auth/login")
def login(request: LoginRequest):
    email = request.email.strip().lower()
    user = users_collection.find_one({"email": email, "active": True})
    if not user or not verify_password(request.password, user.get("password_salt", ""), user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return {"access_token": make_token(user), "token_type": "bearer", "user": serialize_document(user)}

@app.get("/auth/me")
def current_user(user=Depends(get_current_user)):
    return user

@app.get("/auth/users")
def list_users(_admin=Depends(require_admin)):
    return [serialize_document(item) for item in users_collection.find({}, {"password_hash": 0, "password_salt": 0}).sort("created_at", ASCENDING)]

@app.patch("/auth/users/{user_id}/active")
def set_user_active(user_id: str, active: bool, admin=Depends(require_admin)):
    try:
        object_id = ObjectId(user_id)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid user ID")
    if user_id == admin["id"] and not active:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    result = users_collection.update_one({"_id": object_id}, {"$set": {"active": active}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User access updated"}

@app.get("/products")
def get_products(_user=Depends(get_current_user)):
    try:
        return [serialize_document(product) for product in products_collection.find().sort("name", ASCENDING)]
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not retrieve products")

@app.post("/products", status_code=201)
def create_product(product: Product, user=Depends(require_admin)):
    data = product.model_dump()
    data["sku"] = data["sku"].strip()
    existing = products_collection.find_one({"sku": data["sku"]})
    if existing:
        raise HTTPException(status_code=409, detail="A product with this SKU already exists")
    try:
        result = products_collection.insert_one(data)
        saved = products_collection.find_one({"_id": result.inserted_id})
        record_movement(result.inserted_id, saved["name"], "Stock In", saved["quantity"], user)
        return serialize_document(saved)
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not save product")

@app.patch("/products/{product_id}/stock")
def update_product_stock(product_id: str, stock_update: StockUpdate, user=Depends(get_current_user)):
    try:
        object_id = ObjectId(product_id)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid product ID")
    try:
        existing = products_collection.find_one({"_id": object_id})
        if existing is None:
            raise HTTPException(status_code=404, detail="Product not found")
        previous_quantity = int(existing.get("quantity", 0))
        updated_quantity = stock_update.quantity
        result = products_collection.update_one({"_id": object_id}, {"$set": {"quantity": updated_quantity}})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Product not found")
        delta = updated_quantity - previous_quantity
        record_movement(object_id, existing["name"], "Stock In" if delta > 0 else "Stock Out", abs(delta), user)
        return serialize_document(products_collection.find_one({"_id": object_id}))
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not update product stock")

@app.get("/warehouses")
def get_warehouses(_user=Depends(get_current_user)):
    try:
        return [serialize_document(item) for item in warehouses_collection.find().sort("name", ASCENDING)]
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not retrieve warehouses")

@app.post("/warehouses", status_code=201)
def create_warehouse(warehouse: Warehouse, _admin=Depends(require_admin)):
    try:
        data = warehouse.model_dump()
        result = warehouses_collection.insert_one(data)
        return serialize_document(warehouses_collection.find_one({"_id": result.inserted_id}))
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not save warehouse")

@app.delete("/warehouses/{warehouse_id}")
def delete_warehouse(warehouse_id: str, _admin=Depends(require_admin)):
    try:
        result = warehouses_collection.delete_one({"_id": ObjectId(warehouse_id)})
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid warehouse ID")
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not delete warehouse")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Warehouse not found")
    return {"message": "Warehouse deleted"}

@app.get("/suppliers")
def get_suppliers(_user=Depends(get_current_user)):
    try:
        return [serialize_document(item) for item in suppliers_collection.find().sort("name", ASCENDING)]
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not retrieve suppliers")

@app.post("/suppliers", status_code=201)
def create_supplier(supplier: Supplier, _admin=Depends(require_admin)):
    try:
        data = supplier.model_dump()
        result = suppliers_collection.insert_one(data)
        return serialize_document(suppliers_collection.find_one({"_id": result.inserted_id}))
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not save supplier")

@app.delete("/suppliers/{supplier_id}")
def delete_supplier(supplier_id: str, _admin=Depends(require_admin)):
    try:
        result = suppliers_collection.delete_one({"_id": ObjectId(supplier_id)})
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid supplier ID")
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not delete supplier")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Supplier not found")
    return {"message": "Supplier deleted"}

@app.get("/movements")
def get_movements(_user=Depends(get_current_user)):
    try:
        return [serialize_document(item) for item in movements_collection.find().sort("_id", DESCENDING).limit(500)]
    except PyMongoError:
        raise HTTPException(status_code=500, detail="Could not retrieve stock movements")
