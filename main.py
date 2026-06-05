import sqlite3
from typing import Optional
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from passlib.context import CryptContext

# --- CONFIGURĂRI INIȚIALE ---
SECRET_KEY = "cheie_secreta_super_sigura_pentru_laborator"
ALGORITHM = "HS256"

app = FastAPI(title="Gestionar Sarcini API")

# --- CONFIGURARE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="autentificare")

# INITIALIZARE BAZĂ DE DATE SQLITE
def init_db():
    # Modifică linia de mai jos:
    conn = sqlite3.connect("sarcini.db", check_same_thread=False)
    cursor = conn.cursor()
    # ... restul codului din init_db rămâne neschimbat ...
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS utilizatori (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            parola_hash TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sarcini (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utilizator_id INTEGER NOT NULL,
            titlu TEXT NOT NULL,
            descriere TEXT,
            finalizata INTEGER DEFAULT 0,
            FOREIGN KEY (utilizator_id) REFERENCES utilizatori (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    # Modifică linia de mai jos:
    conn = sqlite3.connect("sarcini.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# --- MODELE PYDANTIC ---
class UtilizatorInregistrare(BaseModel):
    username: str
    parola: str

class SarcinaCreare(BaseModel):
    titlu: str
    descriere: Optional[str] = None

class SarcinaActualizare(BaseModel):
    titlu: Optional[str] = None
    descriere: Optional[str] = None

# --- FUNCȚII AJUTĂTOARE SECURITATE ---
def verifica_parola(parola_simpla, parola_hash):
    return pwd_context.verify(parola_simpla, parola_hash)

def genereaza_parola_hash(parola):
    return pwd_context.hash(parola)

def creeaza_token_acces(date: dict):
    return jwt.encode(date, SECRET_KEY, algorithm=ALGORITHM)

async def obtine_utilizator_curent(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    eroare_autentificare = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalid sau expirat",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise eroare_autentificare
    except jwt.PyJWTError:
        raise eroare_autentificare
        
    cursor = db.cursor()
    cursor.execute("SELECT id, username FROM utilizatori WHERE username = ?", (username,))
    utilizator = cursor.fetchone()
    if utilizator is None:
        raise eroare_autentificare
    return dict(utilizator)

# --- ENDPOINT-URI AUTENTIFICARE ---

@app.post("/inregistrare", status_code=201)
def inregistrare(r: UtilizatorInregistrare, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM utilizatori WHERE username = ?", (r.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Numele de utilizator există deja")
    
    hash_p = genereaza_parola_hash(r.parola)
    cursor.execute("INSERT INTO utilizatori (username, parola_hash) VALUES (?, ?)", (r.username, hash_p))
    db.commit()
    return {"message": "Utilizator creat cu succes"}

@app.post("/autentificare")
def autentificare(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM utilizatori WHERE username = ?", (form_data.username,))
    utilizator = cursor.fetchone()
    
    if not utilizator or not verifica_parola(form_data.password, utilizator["parola_hash"]):
        raise HTTPException(status_code=400, detail="Nume de utilizator sau parolă incorecte")
    
    token_acces = creeaza_token_acces(date={"sub": utilizator["username"]})
    return {"access_token": token_acces, "token_type": "bearer"}

# --- ENDPOINT-URI SARCINI ---

@app.get("/sarcini")
def obtine_sarcini(
    doar_nefinalizate: bool = False, 
    utilizator_curent: dict = Depends(obtine_utilizator_curent), 
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    if doar_nefinalizate:
        cursor.execute(
            "SELECT id, titlu, descriere, finalizata FROM sarcini WHERE utilizator_id = ? AND finalizata = 0", 
            (utilizator_curent["id"],)
        )
    else:
        cursor.execute(
            "SELECT id, titlu, descriere, finalizata FROM sarcini WHERE utilizator_id = ?", 
            (utilizator_curent["id"],)
        )
    
    sarcini_rows = cursor.fetchall()
    rezultat = []
    for row in sarcini_rows:
        rezultat.append({
            "id": row["id"],
            "titlu": row["titlu"],
            "descriere": row["descriere"],
            "finalizata": bool(row["finalizata"])
        })
    return rezultat

@app.post("/sarcini", status_code=201)
def creeaza_sarcina(
    s: SarcinaCreare, 
    utilizator_curent: dict = Depends(obtine_utilizator_curent), 
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO sarcini (utilizator_id, titlu, descriere, finalizata) VALUES (?, ?, ?, 0)",
        (utilizator_curent["id"], s.titlu, s.descriere)
    )
    db.commit()
    return {"id": cursor.lastrowid, "titlu": s.titlu, "descriere": s.descriere, "finalizata": False}

@app.put("/sarcini/{sarcina_id}")
def actualizeaza_sarcina(
    sarcina_id: int, 
    s: SarcinaActualizare, 
    utilizator_curent: dict = Depends(obtine_utilizator_curent), 
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM sarcini WHERE id = ? AND utilizator_id = ?", (sarcina_id, utilizator_curent["id"]))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Sarcina nu a fost găsită")
    
    if s.titlu is not None and s.descriere is not None:
        cursor.execute("UPDATE sarcini SET titlu = ?, descriere = ? WHERE id = ?", (s.titlu, s.descriere, sarcina_id))
    elif s.titlu is not None:
        cursor.execute("UPDATE sarcini SET titlu = ? WHERE id = ?", (s.titlu, sarcina_id))
    elif s.descriere is not None:
        cursor.execute("UPDATE sarcini SET descriere = ? WHERE id = ?", (s.descriere, sarcina_id))
        
    db.commit()
    return {"message": "Sarcina a fost actualizată"}

@app.patch("/sarcini/{sarcina_id}/finalizeaza")
def finalizeaza_sarcina(
    sarcina_id: int, 
    utilizator_curent: dict = Depends(obtine_utilizator_curent), 
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM sarcini WHERE id = ? AND utilizator_id = ?", (sarcina_id, utilizator_curent["id"]))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Sarcina nu a fost găsită")
        
    cursor.execute("UPDATE sarcini SET finalizata = 1 WHERE id = ?", (sarcina_id,))
    db.commit()
    return {"message": "Sarcina a fost finalizată"}

@app.delete("/sarcini/{sarcina_id}")
def sterge_sarcina(
    sarcina_id: int, 
    utilizator_curent: dict = Depends(obtine_utilizator_curent), 
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM sarcini WHERE id = ? AND utilizator_id = ?", (sarcina_id, utilizator_curent["id"]))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Sarcina nu a fost găsită")
        
    cursor.execute("DELETE FROM sarcini WHERE id = ?", (sarcina_id,))
    db.commit()
    return {"message": "Sarcina a fost ștearsă"}
