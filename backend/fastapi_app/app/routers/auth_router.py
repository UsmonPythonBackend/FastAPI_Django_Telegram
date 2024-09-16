from fastapi import APIRouter, HTTPException, status
from backend.fastapi_app.app.schemas import UserRegisterSchema, UserLoginSchema
from backend.fastapi_app.app.database import Session, ENGINE
from backend.fastapi_app.app.models import User
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

session = Session(bind=ENGINE)

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

@router.get("/")
async def auth_router():
    return HTTPException(status_code=status.HTTP_200_OK, detail="Auth page")

@router.post("/register")
async def auth_register_user(request: UserRegisterSchema):
    check_user = session.query(User).filter(
        or_(
            User.username == request.username,
            User.email == request.email
        )
    ).first()
    if check_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    new_user = User(
        username=request.username,
        email=request.email,
        password=generate_password_hash(request.password)
    )
    session.add(new_user)
    session.commit()
    return HTTPException(status_code=status.HTTP_201_CREATED, detail="User registered")

@router.post("/login")
async def auth_login_user(request: UserLoginSchema):
    check_user = session.query(User).filter(
        or_(
            User.username == request.username_or_email,
            User.email == request.username_or_email
        )
    ).first()
    if check_user and check_password_hash(check_user.password, request.password):
        return HTTPException(status_code=status.HTTP_200_OK, detail="User logged in")

    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")