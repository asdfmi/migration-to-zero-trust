# protected-resource

Minimal HTTP service that represents a protected resource for the Zero Trust MVP.

## Run
```bash
python3 protected-resource/server.py
```

## Health check
```bash
curl http://localhost:8080/healthz
```

## Notes
- Listens on 0.0.0.0:8080
- Only `/healthz` returns 200; all other paths return 404
