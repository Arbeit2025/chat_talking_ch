"""Chat Talking: a small, anonymous, moderated current-events forum."""
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine, delete, func, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

ROOT = Path(__file__).resolve().parent
CATEGORIES = ("ニュース速報", "政治", "経済", "国際", "社会", "科学・技術", "雑談")
PRODUCTION = os.getenv("APP_ENV", "development").lower() == "production"
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
if PRODUCTION and (not SECRET_KEY or len(SECRET_KEY) < 32 or len(ADMIN_PASSWORD) < 12):
    raise RuntimeError("Production needs SECRET_KEY (32+ chars) and ADMIN_PASSWORD (12+ chars)")
SECRET_KEY = SECRET_KEY or secrets.token_urlsafe(48)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./chat_talking.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
Session = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Topic(Base):
    __tablename__ = "topics"
    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    bumped_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    replies: Mapped[int] = mapped_column(Integer, default=0)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)


class Reply(Base):
    __tablename__ = "replies"
    __table_args__ = (UniqueConstraint("topic_id", "number"), Index("ix_reply_topic_num", "topic_id", "number"))
    id: Mapped[int] = mapped_column(primary_key=True)
    topic_id: Mapped[int] = mapped_column(ForeignKey("topics.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))
    target_id: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class RateEvent(Base):
    __tablename__ = "rate_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)
app = FastAPI(title="Chat Talking", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="chat-talking-admin")
csrf_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="chat-talking-csrf")
env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=select_autoescape(["html"]))


def local_time(value):
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone(timedelta(hours=9))).strftime("%m/%d %H:%M")


def anchors(value, topic_id):
    """Escape all text before turning >>number into a per-topic reply link."""
    parts = []
    prev = 0
    for match in re.finditer(r">>(\d{1,7})", value or ""):
        parts.append(escape(value[prev:match.start()]))
        number = int(match.group(1))
        page = (number - 2) // 50 + 1 if number >= 2 else 1
        parts.append(Markup('<a href="/t/%d?page=%d#res-%d">&gt;&gt;%d</a>' % (topic_id, page, number, number)))
        prev = match.end()
    parts.append(escape((value or "")[prev:]))
    return Markup("").join(parts)


env.filters["jst"] = local_time
env.filters["anchors"] = anchors


def page(request, template, status=200, **context):
    token = getattr(request.state, "csrf", "")
    html = env.get_template(template).render(request=request, categories=CATEGORIES, csrf=token,
                                              admin=admin_signed_in(request), **context)
    return HTMLResponse(html, status_code=status)


def now():
    return datetime.now(timezone.utc)


def client_key(request):
    # Uvicorn must accept forwarding headers only from a trusted reverse proxy.
    address = request.client.host if request.client else "unknown"
    return hmac.new(SECRET_KEY.encode(), address.encode(), hashlib.sha256).hexdigest()


def rate_check(db, request, action, limit, window_seconds=600):
    cutoff = now() - timedelta(seconds=window_seconds)
    key = client_key(request)
    used = db.scalar(select(func.count()).select_from(RateEvent).where(
        RateEvent.key == key, RateEvent.action == action, RateEvent.created_at > cutoff))
    if used >= limit:
        raise HTTPException(429, "投稿回数の上限です。しばらくしてからお試しください。")
    db.add(RateEvent(key=key, action=action, created_at=now()))
    # Delete ancient records opportunistically. No raw client IP is stored.
    db.execute(delete(RateEvent).where(RateEvent.created_at < now() - timedelta(days=2)))


def admin_signed_in(request):
    signed = request.cookies.get("ct_admin")
    if not signed:
        return False
    try:
        return serializer.loads(signed, max_age=12 * 60 * 60) == "authenticated"
    except (BadSignature, SignatureExpired):
        return False


def need_admin(request):
    if not admin_signed_in(request):
        raise HTTPException(403, "管理者ログインが必要です")


def need_csrf(request, data):
    expected = request.cookies.get("ct_csrf", "")
    supplied = str(data.get("_csrf", ""))
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(403, "フォームの有効期限が切れました。ページを再読み込みしてください。")


@app.middleware("http")
async def protection(request, call_next):
    token = request.cookies.get("ct_csrf")
    try:
        if not token or len(token) > 200:
            raise BadSignature("missing")
        csrf_serializer.loads(token, max_age=86400)
    except (BadSignature, SignatureExpired):
        token = csrf_serializer.dumps(secrets.token_urlsafe(32))
    request.state.csrf = token
    response = await call_next(request)
    if request.cookies.get("ct_csrf") != token:
        response.set_cookie("ct_csrf", token, httponly=True, secure=PRODUCTION, samesite="lax", max_age=86400)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    return page(request, "error.html", status=exc.status_code, message=str(exc.detail))


@app.get("/", response_class=HTMLResponse)
def home(request: Request, category: str = "", sort: str = "active", q: str = "", page_num: int = 1):
    category = category if category in CATEGORIES else ""
    sort = sort if sort in ("active", "new", "popular") else "active"
    page_num = min(max(1, page_num), 1000)
    q = q.strip()[:80]
    with Session() as db:
        query = select(Topic).where(Topic.hidden.is_(False))
        if category:
            query = query.where(Topic.category == category)
        if q:
            literal = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            query = query.where(Topic.title.ilike(f"%{literal}%", escape="\\"))
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        column = {"active": Topic.bumped_at, "new": Topic.created_at, "popular": Topic.replies}[sort]
        topics = db.scalars(query.order_by(column.desc(), Topic.id.desc()).offset((page_num - 1) * 20).limit(20)).all()
        popular = db.scalars(select(Topic).where(Topic.hidden.is_(False)).order_by(Topic.replies.desc(), Topic.id.desc()).limit(5)).all()
    def link_to(p):
        return "/?" + urlencode({"category": category, "sort": sort, "q": q, "page_num": p})
    return page(request, "home.html", topics=topics, popular=popular, selected=category,
                sort=sort, query=q, current=page_num, total=total, prev_link=link_to(page_num - 1),
                next_link=link_to(page_num + 1))


@app.get("/new", response_class=HTMLResponse)
def new_topic(request: Request):
    return page(request, "new.html")


@app.post("/topics")
async def create_topic(request: Request):
    data = await request.form()
    need_csrf(request, data)
    title, body, category = str(data.get("title", "")).strip(), str(data.get("body", "")).strip(), str(data.get("category", ""))
    if not (3 <= len(title) <= 120 and 5 <= len(body) <= 5000 and category in CATEGORIES):
        raise HTTPException(400, "タイトルは3〜120文字、本文は5〜5000文字で、カテゴリーを指定してください。")
    with Session.begin() as db:
        rate_check(db, request, "topic", 3)
        topic = Topic(title=title, body=body, category=category)
        db.add(topic)
        db.flush()
        topic_id = topic.id
    return RedirectResponse(f"/t/{topic_id}", status_code=303)


@app.get("/t/{topic_id}", response_class=HTMLResponse)
def topic_detail(request: Request, topic_id: int, page_num: int = 1):
    page_num = min(max(1, page_num), 1000)
    with Session() as db:
        topic = db.get(Topic, topic_id)
        if not topic or topic.hidden:
            raise HTTPException(404, "このスレッドは見つかりません。")
        posts = db.scalars(select(Reply).where(Reply.topic_id == topic_id).order_by(Reply.number).offset((page_num - 1)*50).limit(50)).all()
    return page(request, "topic.html", topic=topic, posts=posts, current=page_num)


@app.post("/t/{topic_id}/replies")
async def create_reply(request: Request, topic_id: int):
    data = await request.form()
    need_csrf(request, data)
    body = str(data.get("body", "")).strip()
    if not 1 <= len(body) <= 2000:
        raise HTTPException(400, "返信は1〜2000文字で入力してください。")
    with Session.begin() as db:
        rate_check(db, request, "reply", 12)
        # Atomic counter update assigns unique reply numbers under concurrency.
        number = db.scalar(update(Topic).where(Topic.id == topic_id, Topic.hidden.is_(False), Topic.locked.is_(False))
                           .values(replies=Topic.replies + 1, bumped_at=now()).returning(Topic.replies))
        if number is None:
            raise HTTPException(404, "このスレッドは存在しないか、書き込み停止中です。")
        db.add(Reply(topic_id=topic_id, number=number + 1, body=body))
    return RedirectResponse(f"/t/{topic_id}?page_num={(number - 1)//50 + 1}#res-{number + 1}", status_code=303)


@app.post("/reports")
async def report_post(request: Request):
    data = await request.form()
    need_csrf(request, data)
    kind = str(data.get("kind", ""))
    reason = str(data.get("reason", "")).strip()
    try:
        target = int(data.get("target_id", 0))
    except (ValueError, TypeError):
        target = 0
    if kind not in ("topic", "reply") or not (2 <= len(reason) <= 300) or target <= 0:
        raise HTTPException(400, "通報内容を確認してください。")
    with Session.begin() as db:
        obj = db.get(Topic if kind == "topic" else Reply, target)
        if not obj or obj.hidden:
            raise HTTPException(404, "投稿が見つかりません。")
        rate_check(db, request, "report", 5)
        db.add(Report(kind=kind, target_id=target, reason=reason))
        redirect_id = obj.id if kind == "topic" else obj.topic_id
    return RedirectResponse(f"/t/{redirect_id}?reported=1", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    if not admin_signed_in(request):
        return page(request, "admin_login.html", enabled=bool(ADMIN_PASSWORD))
    with Session() as db:
        reports = db.scalars(select(Report).where(Report.resolved.is_(False)).order_by(Report.id.desc()).limit(100)).all()
        details = []
        for r in reports:
            target = db.get(Topic if r.kind == "topic" else Reply, r.target_id)
            details.append((r, target))
    return page(request, "admin.html", details=details)


@app.post("/admin/login")
async def admin_login(request: Request):
    data = await request.form()
    need_csrf(request, data)
    with Session.begin() as db:
        rate_check(db, request, "login", 5)
    if not ADMIN_PASSWORD or not hmac.compare_digest(str(data.get("password", "")), ADMIN_PASSWORD):
        raise HTTPException(403, "パスワードが違います。")
    result = RedirectResponse("/admin", status_code=303)
    result.set_cookie("ct_admin", serializer.dumps("authenticated"), httponly=True, secure=PRODUCTION, samesite="strict", max_age=12*60*60)
    return result


@app.post("/admin/logout")
async def admin_logout(request: Request):
    data = await request.form()
    need_csrf(request, data)
    need_admin(request)
    result = RedirectResponse("/", status_code=303)
    result.delete_cookie("ct_admin")
    return result


@app.post("/admin/moderate")
async def moderate(request: Request):
    data = await request.form()
    need_csrf(request, data)
    need_admin(request)
    kind, action = str(data.get("kind", "")), str(data.get("action", ""))
    try:
        target = int(data.get("target_id", 0))
    except (ValueError, TypeError):
        target = 0
    if kind not in ("topic", "reply", "report") or action not in ("hide", "lock", "resolve") or target <= 0:
        raise HTTPException(400, "不正な操作です。")
    if (kind == "report") != (action == "resolve") or (action == "lock" and kind != "topic"):
        raise HTTPException(400, "不正な操作です。")
    with Session.begin() as db:
        obj = db.get({"topic": Topic, "reply": Reply, "report": Report}[kind], target)
        if not obj:
            raise HTTPException(404, "対象が見つかりません。")
        if action == "hide":
            obj.hidden = True
        elif action == "lock":
            obj.locked = True
        else:
            obj.resolved = True
    return RedirectResponse("/admin", status_code=303)


@app.get("/health")
def health():
    with Session() as db:
        db.execute(select(1)).scalar()
    return JSONResponse({"ok": True})
