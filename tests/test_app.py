import importlib
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def board(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("SECRET_KEY", "a" * 48)
    monkeypatch.setenv("ADMIN_PASSWORD", "a-long-admin-password")
    monkeypatch.delenv("APP_ENV", raising=False)
    import app
    importlib.reload(app)
    with TestClient(app.app) as client:
        yield client, app


def csrf(client, url="/"):
    client.get(url)
    return client.cookies.get("ct_csrf")


def thread(client, title="テストスレッド"):
    token = csrf(client)
    result = client.post("/topics", data={"_csrf": token, "category": "政治", "title": title,
                                          "body": "これはテスト本文です。"}, follow_redirects=False)
    assert result.status_code == 303
    return result.headers["location"]


def test_empty_and_health(board):
    client, _ = board
    assert "いまの話題を" in client.get("/").text
    assert client.get("/health").json() == {"ok": True}


def test_topic_reply_search_and_anchor_escaping(board):
    client, _ = board
    path = thread(client)
    assert "テストスレッド" in client.get(path).text
    token = csrf(client, path)
    res = client.post(path + "/replies", data={"_csrf": token, "body": '>>1 <script>alert(1)</script>'}, follow_redirects=False)
    assert res.status_code == 303
    html = client.get(path).text
    assert '&lt;script&gt;' in html
    assert '<script>' not in html
    assert '&gt;&gt;1</a>' in html
    assert '1 レス' in html
    assert 'テストスレッド' in client.get('/?q=テスト').text
    assert 'class="topic-card"' not in client.get('/?q=存在しない').text


def test_validation_and_csrf(board):
    client, _ = board
    assert client.post('/topics', data={'category':'政治', 'title':'good', 'body':'content'}).status_code == 403
    token = csrf(client)
    assert client.post('/topics', data={'_csrf':token, 'category':'政治', 'title':'a', 'body':'content'}).status_code == 400
    assert client.post('/topics', data={'_csrf':token, 'category':'none', 'title':'valid', 'body':'content'}).status_code == 400
    assert client.post('/reports', data={'_csrf':token, 'kind':'reply', 'target_id':9999, 'reason':'invalid'}).status_code == 404


def test_reporting_admin_moderation(board):
    client, _ = board
    path = thread(client)
    token = csrf(client)
    assert client.post('/reports', data={'_csrf':token, 'kind':'topic', 'target_id':path.split('/')[-1], 'reason':'不適切な投稿'}, follow_redirects=False).status_code == 303
    assert client.get('/admin').status_code == 200
    assert client.post('/admin/moderate', data={'_csrf':token, 'kind':'topic', 'target_id':1, 'action':'hide'}).status_code == 403
    assert client.post('/admin/login', data={'_csrf':token, 'password':'wrong'}).status_code == 403
    assert client.post('/admin/login', data={'_csrf':token, 'password':'a-long-admin-password'}, follow_redirects=False).status_code == 303
    assert '不適切な投稿' in client.get('/admin').text
    assert client.post('/admin/moderate', data={'_csrf':token, 'kind':'topic', 'target_id':1, 'action':'hide'}, follow_redirects=False).status_code == 303
    assert client.get(path).status_code == 404
    assert client.post('/admin/moderate', data={'_csrf':token, 'kind':'report', 'target_id':1, 'action':'resolve'}, follow_redirects=False).status_code == 303
    assert '未対応の通報はありません' in client.get('/admin').text
    assert client.post('/admin/logout', data={'_csrf':token}, follow_redirects=False).status_code == 303
    assert '管理者ログイン' in client.get('/admin').text


def test_rate_limits(board):
    client, _ = board
    token = csrf(client)
    for n in range(3):
        assert client.post('/topics', data={'_csrf':token, 'category':'政治', 'title':f'話題 {n}', 'body':'本文のテストです'}, follow_redirects=False).status_code == 303
    assert client.post('/topics', data={'_csrf':token, 'category':'政治', 'title':'話題 4', 'body':'本文のテストです'}).status_code == 429


def test_reply_lock_and_category(board):
    client, _ = board
    path = thread(client)
    token = csrf(client)
    assert 'テストスレッド' in client.get('/?category=政治').text
    assert 'class="topic-card"' not in client.get('/?category=国際').text
    client.post('/admin/login', data={'_csrf':token, 'password':'a-long-admin-password'})
    assert client.post('/admin/moderate', data={'_csrf':token, 'kind':'topic', 'target_id':1, 'action':'lock'}, follow_redirects=False).status_code == 303
    assert client.post(path + '/replies', data={'_csrf':token, 'body':'new reply'}).status_code == 404


def test_anchor_safety_outside_tags(board):
    _, app = board
    html = str(app.anchors('<img src=x> >>8 & "', 15))
    assert '<img' not in html
    assert '&lt;img' in html
    assert '/t/15?page_num=1#res-8' in html


def test_production_requires_secrets(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.delenv('SECRET_KEY', raising=False)
    monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
    with pytest.raises(RuntimeError):
        import app
        importlib.reload(app)
