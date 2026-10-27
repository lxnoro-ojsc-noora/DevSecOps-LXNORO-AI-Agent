import pytest

from devsecops_agent import github_io as gh


class FakeResp:
    def __init__(self, status=200, payload=None, chunks=()):
        self.status_code = status
        self._payload = {} if payload is None else payload
        self._chunks = chunks

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=65536):
        yield from self._chunks


class FakeHTTP:
    def __init__(self, routes, zip_resp=None):
        self.routes = routes
        self.zip_resp = zip_resp
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url, json, headers))
        for (m, suffix), resp in self.routes.items():
            if m == method and url.endswith(suffix):
                return resp
        return FakeResp(404, {"message": "not found"})

    def get(self, url, headers=None, stream=False, timeout=None):
        self.calls.append(("GET", url, None, headers))
        return self.zip_resp


@pytest.mark.parametrize(
    "url,owner,repo,ref",
    [
        ("https://github.com/o/r", "o", "r", ""),
        ("https://github.com/o/r.git", "o", "r", ""),
        ("https://github.com/o/r/", "o", "r", ""),
        ("github.com/o/r/tree/feat/x", "o", "r", "feat/x"),
        ("o/r", "o", "r", ""),
    ],
)
def test_parse_repo_url(url, owner, repo, ref):
    r = gh.parse_repo_url(url)
    assert (r.owner, r.repo, r.ref) == (owner, repo, ref)


@pytest.mark.parametrize(
    "url", ["", "https://gitlab.com/o/r", "https://github.com/o", "https://github.com/o/r/issues",
            "https://evil.com/github.com/o/r", "https://github.com/../r"]
)
def test_parse_repo_url_rejects(url):
    with pytest.raises(gh.GitHubError):
        gh.parse_repo_url(url)


def test_download_ok_and_never_sends_credentials():
    http = FakeHTTP({}, FakeResp(200, chunks=[b"abc", b"def"]))
    data = gh.download_repo_zip(gh.parse_repo_url("o/r"), http=http)
    assert data == b"abcdef"
    assert "Authorization" not in http.calls[0][3]


def test_download_errors_and_size_limit():
    ref = gh.parse_repo_url("o/r")
    with pytest.raises(gh.GitHubError):
        gh.download_repo_zip(ref, http=FakeHTTP({}, FakeResp(404)))
    with pytest.raises(gh.GitHubError):
        gh.download_repo_zip(ref, http=FakeHTTP({}, FakeResp(403)))
    with pytest.raises(gh.GitHubError):
        gh.download_repo_zip(ref, http=FakeHTTP({}, FakeResp(200, chunks=[b"x" * 20])), max_bytes=10)


def good_routes():
    return {
        ("GET", "/repos/o/r"): FakeResp(200, {"default_branch": "main", "permissions": {"push": True}}),
        ("GET", "/repos/o/r/git/ref/heads/main"): FakeResp(200, {"object": {"sha": "base1"}}),
        ("GET", "/repos/o/r/git/commits/base1"): FakeResp(200, {"tree": {"sha": "tree1"}}),
        ("GET", "/repos/o/r/git/trees/tree1?recursive=1"): FakeResp(
            200, {"tree": [{"path": "a.py", "mode": "100755", "type": "blob"}]}),
        ("POST", "/repos/o/r/git/blobs"): FakeResp(201, {"sha": "blob1"}),
        ("POST", "/repos/o/r/git/trees"): FakeResp(201, {"sha": "tree2"}),
        ("POST", "/repos/o/r/git/commits"): FakeResp(201, {"sha": "commit2"}),
        ("POST", "/repos/o/r/git/refs"): FakeResp(201, {"ref": "refs/heads/fixes"}),
        ("POST", "/repos/o/r/pulls"): FakeResp(201, {"html_url": "https://github.com/o/r/pull/7", "number": 7}),
    }


def test_publish_creates_branch_commit_and_pr_without_force():
    http = FakeHTTP(good_routes())
    res = gh.publish_changes("tok", "o/r", "main", "fixes", {"a.py": "x = 1\n"}, "msg", "title", "body", http=http)
    assert (res.branch, res.commit_sha, res.pr_url, res.pr_number) == ("fixes", "commit2", "https://github.com/o/r/pull/7", 7)
    methods = {c[0] for c in http.calls}
    assert methods <= {"GET", "POST"}
    tree_post = [c for c in http.calls if c[0] == "POST" and c[1].endswith("/git/trees")][0]
    assert tree_post[2]["tree"][0]["mode"] == "100755"
    assert tree_post[2]["base_tree"] == "tree1"


@pytest.mark.parametrize("branch", ["main", "master"])
def test_publish_refuses_default_branch(branch):
    http = FakeHTTP(good_routes())
    with pytest.raises(gh.GitHubError):
        gh.publish_changes("tok", "o/r", "main", branch, {"a.py": "x"}, "m", "t", "b", http=http)
    assert all(c[0] == "GET" for c in http.calls)


def test_publish_requires_push_and_changes():
    routes = good_routes()
    routes[("GET", "/repos/o/r")] = FakeResp(200, {"default_branch": "main", "permissions": {"push": False}})
    with pytest.raises(gh.GitHubError):
        gh.publish_changes("tok", "o/r", "main", "fixes", {"a.py": "x"}, "m", "t", "b", http=FakeHTTP(routes))
    with pytest.raises(gh.GitHubError):
        gh.publish_changes("tok", "o/r", "main", "fixes", {}, "m", "t", "b", http=FakeHTTP(good_routes()))


def test_error_messages_never_contain_token():
    http = FakeHTTP({("GET", "/repos/o/r"): FakeResp(401, {"message": "Bad credentials SECRETTOKEN"})})
    info = gh.verify_access("SECRETTOKEN", "o/r", http=http)
    assert not info.ok and "SECRETTOKEN" not in info.message


def test_verify_access_reports_push_permission():
    info = gh.verify_access("tok", "o/r", http=FakeHTTP(good_routes()))
    assert info.ok and info.can_push and info.default_branch == "main"


def test_publish_config_disabled_until_all_settings_present():
    assert gh.load_publish_config({}.get) is None
    partial = {"GITHUB_TOKEN": "t", "PUBLISH_REPO": "o/r"}
    assert "PUBLISH_KEY" in gh.publish_blockers(partial.get)
    full = {"GITHUB_TOKEN": "t", "PUBLISH_KEY": "k", "PUBLISH_REPO": "o/r"}
    cfg = gh.load_publish_config(full.get)
    assert cfg and gh.key_matches(cfg, "k") and not gh.key_matches(cfg, "x") and not gh.key_matches(cfg, "")
    assert "t" != repr(cfg) and "token" not in repr(cfg).lower().replace("githubtoken", "")
    assert gh.publish_blockers({**full, "PUBLISH_REPO": "bad"}.get)
