from datetime import datetime, timedelta
from typing import List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

# For password hashing & JWT
from passlib.context import CryptContext
from pydantic import BaseModel, Field

# For SQLite & SQLAlchemy
from sqlalchemy import Column, Float, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# -------------------------------------------------------------------
# Database Configuration
# -------------------------------------------------------------------
# Creates (or uses) 'test.db' in the current directory
DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# -------------------------------------------------------------------
# SQLAlchemy Models
# -------------------------------------------------------------------


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)


class ProductModel(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    price = Column(Float, nullable=False)


class OrderModel(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    total_amount = Column(Float, nullable=False, default=0.0)


class OrderItemModel(Base):
    __tablename__ = "order_items"
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity = Column(Integer, nullable=False)


# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

# -------------------------------------------------------------------
# Pydantic Schemas
# -------------------------------------------------------------------


class UserBase(BaseModel):
    username: str
    full_name: Optional[str] = None


class UserSignUp(UserBase):
    password: str  # plaintext password from the client


class UserOut(UserBase):
    """Returned to the client (omits password)."""


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

# Products


class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float = Field(..., gt=0)


class ProductCreate(ProductBase):
    pass


class ProductOut(ProductBase):
    id: int

# Orders


class OrderItem(BaseModel):
    product_id: int
    quantity: int = Field(..., gt=0)


class OrderCreate(BaseModel):
    items: List[OrderItem]


class OrderOut(BaseModel):
    id: int
    total_amount: float


# -------------------------------------------------------------------
# Security & Auth Config
# -------------------------------------------------------------------
SECRET_KEY = "CHANGE_THIS_TO_SOMETHING_SECURE"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------------------------------------------------------------
# FastAPI App
# -------------------------------------------------------------------
app = FastAPI(title="E-commerce with SQLite & JWT (Hashed Passwords)")

# -------------------------------------------------------------------
# Dependency: Get DB Session
# -------------------------------------------------------------------


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash the plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against stored hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> UserModel:
    """Check for a valid JWT; return the current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = db.query(UserModel).filter(
        UserModel.username == token_data.username).first()
    if user is None:
        raise credentials_exception

    return user

# -------------------------------------------------------------------
# Auth Routes
# -------------------------------------------------------------------


@app.post("/signup", response_model=UserOut, status_code=201)
def signup(user_data: UserSignUp, db: Session = Depends(get_db)):
    """Create a new user account (sign up) with a hashed password."""
    existing_user = db.query(UserModel).filter(
        UserModel.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )

    new_user = UserModel(
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password)  # Hashing here
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserOut(username=new_user.username, full_name=new_user.full_name)


@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Obtain a JWT token via username & password. Password is verified against the stored hash."""
    user = db.query(UserModel).filter(
        UserModel.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserOut)
def get_me(current_user: UserModel = Depends(get_current_user)):
    """Return the currently logged-in user's information."""
    return UserOut(username=current_user.username, full_name=current_user.full_name)

# -------------------------------------------------------------------
# Product Routes (Protected)
# -------------------------------------------------------------------


@app.post("/products", response_model=ProductOut)
def create_product(
    product_data: ProductCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Create a new product (requires valid JWT)."""
    product = ProductModel(
        name=product_data.name,
        description=product_data.description,
        price=product_data.price
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return ProductOut(
        id=product.id,
        name=product.name,
        description=product.description,
        price=product.price
    )


@app.get("/products", response_model=List[ProductOut])
def list_products(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """List all products (requires valid JWT)."""
    products = db.query(ProductModel).all()
    return products


@app.get("/products/{product_id}", response_model=ProductOut)
def get_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Get product by ID (requires valid JWT)."""
    product = db.query(ProductModel).filter(
        ProductModel.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")
    return product


@app.put("/products/{product_id}", response_model=ProductOut)
def update_product(
    product_id: int,
    product_data: ProductCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Update an existing product (requires valid JWT)."""
    product = db.query(ProductModel).filter(
        ProductModel.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    product.name = product_data.name
    product.description = product_data.description
    product.price = product_data.price
    db.commit()
    db.refresh(product)
    return product


@app.delete("/products/{product_id}")
def delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Delete a product (requires valid JWT)."""
    product = db.query(ProductModel).filter(
        ProductModel.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    db.delete(product)
    db.commit()
    return {"detail": "Product deleted."}

# -------------------------------------------------------------------
# Order Routes (Protected)
# -------------------------------------------------------------------


@app.post("/orders", response_model=OrderOut)
def create_order(
    order_data: OrderCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Create a new order with multiple items (requires valid JWT)."""
    new_order = OrderModel(user_id=current_user.id, total_amount=0.0)
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    total = 0.0
    for item in order_data.items:
        product = db.query(ProductModel).filter(
            ProductModel.id == item.product_id).first()
        if not product:
            raise HTTPException(
                status_code=400, detail=f"Product ID {item.product_id} not found.")
        total += product.price * item.quantity

        order_item = OrderItemModel(
            order_id=new_order.id,
            product_id=item.product_id,
            quantity=item.quantity
        )
        db.add(order_item)

    new_order.total_amount = total
    db.commit()
    db.refresh(new_order)

    return OrderOut(id=new_order.id, total_amount=new_order.total_amount)


@app.get("/orders", response_model=List[OrderOut])
def list_orders(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """List all orders (requires valid JWT).
    (Modify to show only the current user's orders if needed.)
    """
    orders = db.query(OrderModel).all()
    return [OrderOut(id=o.id, total_amount=o.total_amount) for o in orders]


@app.get("/orders/{order_id}", response_model=OrderOut)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Get a single order by ID (requires valid JWT)."""
    order = db.query(OrderModel).filter(OrderModel.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    return OrderOut(id=order.id, total_amount=order.total_amount)


# -------------------------------------------------------------------
# Run Server
# -------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
