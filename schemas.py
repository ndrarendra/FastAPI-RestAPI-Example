# schemas.py
from typing import List, Optional
from pydantic import BaseModel, Field

# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    full_name: Optional[str] = None

class UserSignUp(UserBase):
    password: str  # plaintext password from the client

class UserOut(UserBase):
    """Returned to the client (omits password)."""
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- Product Schemas ---
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float = Field(..., gt=0)

class ProductCreate(ProductBase):
    pass

class ProductOut(ProductBase):
    id: int

# --- Order Schemas ---
class OrderItem(BaseModel):
    product_id: int
    quantity: int = Field(..., gt=0)

class OrderCreate(BaseModel):
    items: List[OrderItem]

class OrderOut(BaseModel):
    id: int
    total_amount: float
