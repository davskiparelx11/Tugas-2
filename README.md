from fastapi import FastAPI, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from . import models, schemas, crud
from .database import engine, SessionLocal

# Buat semua tabel di database
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Users CRUD API")

# Dependency untuk database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_role(x_role: str | None = Header(None, alias="X-Role")) -> str:
    if x_role is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="X-Role header required")
    if x_role not in ("admin", "staff"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")
    return x_role


def get_user_id(x_user_id: int | None = Header(None, alias="X-User-Id")) -> int | None:
    return x_user_id


# CREATE - terbuka untuk semua
@app.post("/users/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # unique checks
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    return crud.create_user(db, user)


# READ ALL - hanya admin
@app.get("/users/", response_model=list[schemas.UserResponse])
def read_users(role: str = Depends(get_role), db: Session = Depends(get_db)):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view all users")
    return crud.get_users(db)


# READ BY ID - admin bisa lihat semua, staff hanya lihat miliknya sendiri
@app.get("/users/{user_id}", response_model=schemas.UserResponse)
def read_user(
    user_id: int,
    role: str = Depends(get_role),
    x_user_id: int | None = Depends(get_user_id),
    db: Session = Depends(get_db)
):
    user = crud.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if role == "admin":
        return user
    # staff
    if x_user_id is None:
        raise HTTPException(status_code=403, detail="X-User-Id header required for staff")
    if x_user_id != user_id:
        raise HTTPException(status_code=403, detail="Staff can only view their own data")
    return user


# UPDATE - hanya admin
@app.put("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(user_id: int, user: schemas.UserCreate, role: str = Depends(get_role), db: Session = Depends(get_db)):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update users")
    db_user = crud.update_user(db, user_id, user)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


# DELETE - hanya admin
@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, role: str = Depends(get_role), db: Session = Depends(get_db)):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete users")
    db_user = crud.delete_user(db, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return
