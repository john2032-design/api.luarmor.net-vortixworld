from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/redirect")
def redirect_page():
    target = request.args.get("to")
    if not target or not target.startswith(("http://", "https://")):
        return "Invalid or missing 'to' parameter", 400

    js_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Redirecting...</title>
    </head>
    <body>
      <script>
        setTimeout(() => {{
          location.replace("{target}");
        }}, 3000);
      </script>
    </body>
    </html>
    """

    response = make_response(js_code)
    response.headers["Content-Type"] = "text/html"

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)