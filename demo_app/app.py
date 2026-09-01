"""
Intentionally vulnerable demo e-commerce app (Section 21).

THIS APPLICATION IS DELIBERATELY INSECURE. It exists solely as an authorized
local target for the threat-modeling platform to analyze and test. Never
deploy it anywhere reachable from the internet.

Seeded vulnerabilities:
  1. Broken Object Level Authorization (IDOR) on GET /orders/<id>
     -> any authenticated user can read any other user's order.
  2. Broken Function Level Authorization on POST /admin/users
     -> a non-admin token can still call the admin endpoint.
  3. Weak authentication: /login has no rate limiting/lockout.
  4. Information disclosure: verbose error responses expose internal detail.
  5. Insecure API configuration: permissive CORS + missing security headers.
  6. Business logic flaw: /orders/<id>/apply-coupon can be replayed to stack
     discounts (missing one-time-use enforcement).

Run directly: python demo_app/app.py  (listens on port 8081)
"""
from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    "alice-token": {"user_id": "u1", "role": "user"},
    "bob-token": {"user_id": "u2", "role": "user"},
    # Vuln #2 setup: this is a normal-user token but the admin route doesn't check role properly
}

ORDERS = {
    "o1": {"id": "o1", "owner": "u1", "item": "Laptop", "amount": 1200, "coupon_applied": False},
    "o2": {"id": "o2", "owner": "u2", "item": "Phone", "amount": 800, "coupon_applied": False},
}


@app.after_request
def _permissive_cors(response):
    # Vuln #5: permissive CORS, no real security headers — intentional
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response


def _current_user():
    authorization = request.headers.get("Authorization")
    if not authorization or authorization not in USERS:
        return None
    return USERS[authorization]


@app.route("/login", methods=["POST"])
def login():
    # Vuln #3: no rate limiting / lockout on repeated attempts
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    token_map = {"alice": "alice-token", "bob": "bob-token"}
    if username in token_map and password == "password123":
        return jsonify({"token": token_map[username]})
    # Vuln #4: verbose error leaks whether username exists
    if username in token_map:
        return jsonify({"detail": f"Password incorrect for existing user '{username}'"}), 401
    return jsonify({"detail": f"No such user '{username}' in database"}), 401


@app.route("/orders/<order_id>", methods=["GET"])
def get_order(order_id):
    user = _current_user()
    if not user:
        return jsonify({"detail": "Invalid or missing token"}), 401
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"detail": "Order not found"}), 404
    # Vuln #1 (BOLA/IDOR): no check that order["owner"] == user["user_id"]
    return jsonify(order)


@app.route("/orders/<order_id>/apply-coupon", methods=["POST"])
def apply_coupon(order_id):
    user = _current_user()
    if not user:
        return jsonify({"detail": "Invalid or missing token"}), 401
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"detail": "Order not found"}), 404
    code = request.values.get("code", "")
    # Vuln #6: no idempotency / one-time-use check — can be replayed
    if code == "SAVE10":
        order["amount"] = round(order["amount"] * 0.9, 2)
    return jsonify(order)


@app.route("/admin/users", methods=["POST"])
def admin_create_user():
    user = _current_user()
    if not user:
        return jsonify({"detail": "Invalid or missing token"}), 401
    username = request.values.get("username", "")
    # Vuln #2 (broken function-level authz): should require role == "admin" but doesn't check it
    USERS[f"{username}-token"] = {"user_id": f"u_{username}", "role": "user"}
    return jsonify({"created": username})


@app.route("/")
def root():
    return jsonify({"status": "vulnerable demo app running — authorized use only"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
