from flask import Flask, request, make_response, render_template_string
import json
from urllib.parse import urlparse
import secrets
import base64
import logging
import ipaddress
import html
import hashlib
from typing import Tuple, Union
import os

# For extensions: Assume installed via requirements.txt
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

Compress(app)  # Enable GZIP compression

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

def validate_target(target: str) -> str:
    if not target:
        raise ValueError("Missing 'to' parameter")
    if len(target) > 2048:
        raise ValueError("Invalid 'to' parameter (URL too long)")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Invalid 'to' parameter (must be a valid HTTP/HTTPS URL)")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            raise ValueError("Invalid 'to' parameter (no local/internal redirects)")
    except ValueError:
        pass  # Not an IP, proceed
    return target

def generate_error_response(message: str) -> Tuple[make_response, int]:
    error_html = f"""
    <!DOCTYPE html>
    <html><head><title>Error</title></head><body><h1>400 Bad Request</h1><p>{html.escape(message)}</p></body></html>
    """
    response = make_response(error_html)
    response.headers["Content-Type"] = "text/html"
    return response, 400

def generate_html(target: str, nonce: str) -> str:
    escaped_target = html.escape(target)
    template = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Redirecting...</title>
    </head>
    <body role="alert" aria-live="assertive">
      <p>Redirecting to <a href="{{ escaped_target }}">{{ escaped_target }}</a>...</p>
      <script nonce="{{ nonce }}">
        location.replace({{ target|tojson }});
      </script>
      <noscript>
        <meta http-equiv="refresh" content="0;url={{ escaped_target }}">
        <p>JavaScript is disabled. Click <a href="{{ escaped_target }}">here</a> to redirect.</p>
      </noscript>
    </body>
    </html>
    """
    return render_template_string(template, target=target, nonce=nonce, escaped_target=escaped_target)

@app.route("/redirect")
@limiter.limit("10 per minute")
def redirect_page() -> Union[Tuple[make_response, int], make_response]:
    target = request.args.get("to")
    user_agent = request.user_agent.string
    ip = request.remote_addr
    try:
        target = validate_target(target)
        nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        script_content = f"location.replace({json.dumps(target)});"
        script_hash = hashlib.sha256(script_content.encode()).digest()
        script_hash_b64 = base64.b64encode(script_hash).decode('utf-8')
        js_code = generate_html(target, nonce)
        response = make_response(js_code)
        response.headers["Content-Type"] = "text/html"
        response.headers["Content-Security-Policy"] = f"default-src 'self'; script-src 'nonce-{nonce}' 'sha256-{script_hash_b64}' 'strict-dynamic'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Access-Control-Allow-Origin"] = "*"  # Adjust if needed
        app.logger.info(f"Redirecting to: {target} from IP {ip} UA {user_agent}")
        return response
    except ValueError as e:
        app.logger.warning(f"Invalid redirect attempt: {target} from IP {ip} UA {user_agent} - {str(e)}")
        return generate_error_response(str(e))
    except Exception as e:
        app.logger.error(f"Error in redirect: {str(e)} from IP {ip} UA {user_agent}")
        return generate_error_response("Internal error"), 500

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", 5000)), threaded=True)