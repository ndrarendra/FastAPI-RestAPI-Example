# FastAPI E-commerce API with JWT Login

A small e-commerce backend built with FastAPI and SQLAlchemy. Users sign up and log in, then manage products and place orders that hold several items. Passwords are hashed with bcrypt and every route after login is protected with a JWT bearer token.

## Endpoints

| Method | Path | Login needed | What it does |
| --- | --- | --- | --- |
| POST | `/signup` | No | Create a user |
| POST | `/token` | No | Log in and get a JWT (valid for 30 minutes) |
| GET | `/users/me` | Yes | Current user |
| POST | `/products` | Yes | Add a product |
| GET | `/products` | Yes | List products |
| GET | `/products/{id}` | Yes | One product |
| PUT | `/products/{id}` | Yes | Update a product |
| DELETE | `/products/{id}` | Yes | Delete a product |
| POST | `/orders` | Yes | Place an order with one or more items |
| GET | `/orders` | Yes | Your orders |
| GET | `/orders/{id}` | Yes | One order |

Data lives in a local SQLite file (`test.db`) with four tables: users, products, orders and order items.

## Run it

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

Then open http://127.0.0.1:8000/docs, sign up, use **Authorize** with your username and password, and try the routes from the browser.

## Files

- `app.py`: the whole API (models, schemas, auth and routes)
- `models.py`, `schemas.py`: the same models and schemas split into their own modules
- `templates/`: HTML pages for a product list, product detail and search, not yet connected to `app.py`

`SECRET_KEY` in `app.py` is a placeholder. Set your own value before running this anywhere other than your own machine.
