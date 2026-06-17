# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# 本地 SQLite 数据库文件路径 (会在你运行代码的目录下生成 malconv_test.db)
SQLALCHEMY_DATABASE_URL = "sqlite:///./malconv_test.db"

# 注意：check_same_thread=False 是 SQLite 在 FastAPI (多线程) 中必须要加的参数
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()