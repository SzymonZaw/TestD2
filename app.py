from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "sentinel_research.db"
CONFIGS = [
    "baseline",
    "content_only",
    "policy_only",
    "combined",
]
CONFIG_LABELS = {
    "baseline": "Agent bazowy (bez ochrony)",
    "content_only": "Analiza treści",
    "policy_only": "Egzekwowanie polityk",
    "combined": "Podejście łączone",
}
STATUSES = ["Planowany", "W trakcie", "Ukończony", "Do poprawy"]

st.set_page_config(
    page_title="Sentinel AI Web Shield — Research Manager",
    page_icon="🛡️",
    layout="wide",
)

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS chapters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chapter_no TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Planowany',
            notes TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            attack_type TEXT DEFAULT '',
            description TEXT DEFAULT '',
            expected_outcome TEXT DEFAULT '',
            risk_level TEXT DEFAULT 'Średni',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_id INTEGER NOT NULL,
            configuration TEXT NOT NULL,
            trial_no INTEGER NOT NULL DEFAULT 1,
            attack_success INTEGER NOT NULL DEFAULT 0,
            unauthorized_proposed INTEGER NOT NULL DEFAULT 0,
            unauthorized_executed INTEGER NOT NULL DEFAULT 0,
            benign_flagged INTEGER NOT NULL DEFAULT 0,
            task_success INTEGER NOT NULL DEFAULT 0,
            latency_ms REAL,
            baseline_latency_ms REAL,
            notes TEXT DEFAULT '',
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(scenario_id) REFERENCES scenarios(id)
        );
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            citation_key TEXT DEFAULT '',
            title TEXT NOT NULL,
            authors TEXT DEFAULT '',
            year TEXT DEFAULT '',
            doi_url TEXT DEFAULT '',
            linked_chapter TEXT DEFAULT '',
            notes TEXT DEFAULT ''
        );
        """)
        count = conn.execute("SELECT COUNT(*) FROM chapters").fetchone()[0]
        if count == 0:
            defaults = [
                ("1", "Wprowadzenie"),
                ("2", "Podstawy teoretyczne i przegląd literatury"),
                ("3", "Model zagrożeń i projekt Sentinel AI Web Shield"),
                ("4", "Projekt i implementacja prototypu"),
                ("5", "Metodyka badań eksperymentalnych"),
                ("6", "Wyniki, dyskusja i wnioski końcowe"),
            ]
            now = datetime.now().isoformat(timespec="seconds")
            conn.executemany(
                "INSERT INTO chapters(chapter_no,title,status,notes,updated_at) VALUES(?,?, 'Planowany','',?)",
                [(n, t, now) for n, t in defaults],
            )

def query_df(sql: str, params: tuple = ()) -> pd.DataFrame:
    with connect() as conn:
        return pd.read_sql_query(sql, conn, params=params)

def metric_summary(df: pd.DataFrame) -> dict:
    if df.empty:
        return {}
    attacks = df[df["category"] == "adversarial"]
    benign = df[df["category"] == "benign"]
    proposed = int(attacks["unauthorized_proposed"].sum())
    unauthorized_executed = int(attacks["unauthorized_executed"].sum())
    return {
        "ASR": (100 * attacks["attack_success"].sum() / len(attacks)) if len(attacks) else None,
        "UAER": (100 * unauthorized_executed / proposed) if proposed else None,
        "FPR": (100 * benign["benign_flagged"].sum() / len(benign)) if len(benign) else None,
        "LTCR": (100 * benign["task_success"].sum() / len(benign)) if len(benign) else None,
        "mean_latency": df["latency_ms"].dropna().mean(),
        "n": len(df),
    }

def pct(value: Optional[float]) -> str:
    return "—" if value is None or pd.isna(value) else f"{value:.1f}%"

def dashboard() -> None:
    st.title("🛡️ Sentinel AI Web Shield")
    st.caption("Lokalny menedżer dokumentacji doktoratu i danych eksperymentalnych")
    runs = query_df("""
        SELECT r.*, s.category, s.scenario_key, s.title AS scenario_title
        FROM runs r JOIN scenarios s ON s.id = r.scenario_id
    """)
    chapters = query_df("SELECT * FROM chapters")
    scenarios = query_df("SELECT * FROM scenarios")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rozdziały", len(chapters))
    c2.metric("Scenariusze", len(scenarios))
    c3.metric("Zarejestrowane próby", len(runs))
    c4.metric("Status bazy", "Lokalna SQLite")
    st.subheader("Postęp dokumentacji")
    if not chapters.empty:
        progress = (chapters["status"] == "Ukończony").mean() * 100
        st.progress(float(progress / 100), text=f"Ukończone rozdziały: {progress:.0f}%")
        st.dataframe(chapters[["chapter_no", "title", "status", "updated_at"]], use_container_width=True, hide_index=True)
    st.subheader("Dane eksperymentalne")
    if runs.empty:
        st.info("Brak prób. Dodaj scenariusze i zarejestruj wyniki — aplikacja nie generuje ani nie symuluje wyników badań.")
    else:
        by_config = runs.groupby("configuration").size().rename("Liczba prób").reset_index()
        by_config["Konfiguracja"] = by_config["configuration"].map(CONFIG_LABELS)
        st.plotly_chart(px.bar(by_config, x="Konfiguracja", y="Liczba prób", title="Liczba zarejestrowanych prób"), use_container_width=True)

def page_chapters() -> None:
    st.title("📚 Dokumentacja doktoratu")
    df = query_df("SELECT * FROM chapters ORDER BY CAST(chapter_no AS INTEGER), chapter_no")
    st.dataframe(df[["id", "chapter_no", "title", "status", "notes", "updated_at"]], use_container_width=True, hide_index=True)
    st.subheader("Dodaj rozdział / podrozdział")
    with st.form("add_chapter"):
        a, b = st.columns([1, 3])
        no = a.text_input("Numer", placeholder="np. 5.1")
        title = b.text_input("Tytuł")
        status = st.selectbox("Status", STATUSES)
        notes = st.text_area("Notatki")
        submitted = st.form_submit_button("Zapisz")
    if submitted:
        if not no.strip() or not title.strip():
            st.error("Numer i tytuł są wymagane.")
        else:
            with connect() as conn:
                conn.execute("INSERT INTO chapters(chapter_no,title,status,notes,updated_at) VALUES(?,?,?,?,?)",
                             (no.strip(), title.strip(), status, notes, datetime.now().isoformat(timespec="seconds")))
            st.success("Zapisano rozdział.")
            st.rerun()
    st.subheader("Edytuj istniejący rozdział")
    if not df.empty:
        selected = st.selectbox("Wybierz pozycję", df["id"].tolist(), format_func=lambda x: f"{df.loc[df.id == x, 'chapter_no'].iloc[0]} — {df.loc[df.id == x, 'title'].iloc[0]}")
        item = df[df.id == selected].iloc[0]
        with st.form("edit_chapter"):
            new_status = st.selectbox("Status", STATUSES, index=STATUSES.index(item.status))
            new_notes = st.text_area("Notatki", value=item.notes or "")
            save = st.form_submit_button("Aktualizuj")
        if save:
            with connect() as conn:
                conn.execute("UPDATE chapters SET status=?, notes=?, updated_at=? WHERE id=?",
                             (new_status, new_notes, datetime.now().isoformat(timespec="seconds"), int(selected)))
            st.success("Zaktualizowano.")
            st.rerun()

def page_scenarios() -> None:
    st.title("🧪 Scenariusze eksperymentalne")
    df = query_df("SELECT * FROM scenarios ORDER BY id DESC")
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Nie dodano jeszcze scenariuszy.")
    with st.form("add_scenario"):
        st.subheader("Nowy scenariusz")
        key = st.text_input("Identyfikator", placeholder="np. ADV-001")
        title = st.text_input("Nazwa scenariusza")
        category = st.selectbox("Rodzaj", ["adversarial", "benign"], format_func=lambda x: "Adwersarialny" if x == "adversarial" else "Benign / poprawny")
        attack_type = st.text_input("Typ ataku / kategoria (opcjonalnie)")
        description = st.text_area("Opis i warunki")
        expected = st.text_area("Oczekiwane zachowanie agenta")
        risk = st.selectbox("Poziom ryzyka", ["Niski", "Średni", "Wysoki", "Krytyczny"])
        save = st.form_submit_button("Dodaj scenariusz")
    if save:
        if not key.strip() or not title.strip():
            st.error("Identyfikator i nazwa są wymagane.")
        else:
            try:
                with connect() as conn:
                    conn.execute("""INSERT INTO scenarios(scenario_key,title,category,attack_type,description,expected_outcome,risk_level,created_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (key.strip(), title.strip(), category, attack_type, description, expected, risk, datetime.now().isoformat(timespec="seconds")))
                st.success("Scenariusz dodany.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("Taki identyfikator scenariusza już istnieje.")

def page_runs() -> None:
    st.title("📈 Rejestr prób eksperymentalnych")
    scenarios = query_df("SELECT id, scenario_key, title, category FROM scenarios ORDER BY scenario_key")
    if scenarios.empty:
        st.warning("Najpierw dodaj co najmniej jeden scenariusz.")
        return
    with st.form("add_run"):
        scenario_id = st.selectbox("Scenariusz", scenarios["id"].tolist(),
            format_func=lambda x: f"{scenarios.loc[scenarios.id == x, 'scenario_key'].iloc[0]} — {scenarios.loc[scenarios.id == x, 'title'].iloc[0]}")
        config = st.selectbox("Konfiguracja agenta", CONFIGS, format_func=lambda x: CONFIG_LABELS[x])
        trial = st.number_input("Numer powtórzenia", min_value=1, step=1, value=1)
        st.markdown("**Wyniki obserwacji**")
        attack_success = st.checkbox("Atak zakończył się sukcesem (ASR)")
        proposed = st.number_input("Liczba zaproponowanych nieautoryzowanych działań", min_value=0, step=1, value=0)
        executed = st.number_input("Liczba wykonanych nieautoryzowanych działań", min_value=0, step=1, value=0)
        benign_flagged = st.checkbox("Poprawne zadanie błędnie oznaczone/zablokowane (FPR)")
        task_success = st.checkbox("Poprawne zadanie ukończone (LTCR)")
        latency = st.number_input("Czas wykonania (ms)", min_value=0.0, value=0.0, step=1.0)
        baseline_latency = st.number_input("Czas bazowy dla porównania (ms; opcjonalnie)", min_value=0.0, value=0.0, step=1.0)
        notes = st.text_area("Notatki / uzasadnienie klasyfikacji")
        save = st.form_submit_button("Zapisz próbę")
    if save:
        if executed > proposed:
            st.error("Liczba wykonanych działań nie może przekraczać liczby zaproponowanych.")
        else:
            with connect() as conn:
                conn.execute("""INSERT INTO runs(scenario_id,configuration,trial_no,attack_success,unauthorized_proposed,
                unauthorized_executed,benign_flagged,task_success,latency_ms,baseline_latency_ms,notes,recorded_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (int(scenario_id), config, int(trial), int(attack_success), int(proposed), int(executed),
                 int(benign_flagged), int(task_success), latency or None, baseline_latency or None,
                 notes, datetime.now().isoformat(timespec="seconds")))
            st.success("Próba zapisana.")
            st.rerun()
    runs = query_df("""SELECT r.id, s.scenario_key, s.category, r.configuration, r.trial_no,
        r.attack_success, r.unauthorized_proposed, r.unauthorized_executed, r.benign_flagged,
        r.task_success, r.latency_ms, r.notes, r.recorded_at
        FROM runs r JOIN scenarios s ON s.id=r.scenario_id ORDER BY r.id DESC""")
    st.subheader("Zapisane próby")
    st.dataframe(runs, use_container_width=True, hide_index=True)
    if not runs.empty:
        st.download_button("Pobierz próby jako CSV", runs.to_csv(index=False).encode("utf-8-sig"),
                           "sentinel_runs.csv", "text/csv")

def page_analysis() -> None:
    st.title("📊 Analiza metryk")
    df = query_df("""SELECT r.*, s.category, s.scenario_key, s.title AS scenario_title
        FROM runs r JOIN scenarios s ON s.id=r.scenario_id""")
    if df.empty:
        st.info("Analiza pojawi się po wprowadzeniu danych eksperymentalnych.")
        return
    configs = st.multiselect("Konfiguracje", CONFIGS, default=CONFIGS, format_func=lambda x: CONFIG_LABELS[x])
    df = df[df.configuration.isin(configs)]
    rows = []
    for config in configs:
        part = df[df.configuration == config]
        m = metric_summary(part)
        if m:
            rows.append({"Konfiguracja": CONFIG_LABELS[config], "ASR": pct(m["ASR"]),
                         "UAER": pct(m["UAER"]), "FPR": pct(m["FPR"]),
                         "LTCR": pct(m["LTCR"]), "Śr. czas (ms)": round(m["mean_latency"], 2) if pd.notna(m["mean_latency"]) else "—",
                         "Liczba prób": m["n"]})
    st.subheader("Zestawienie")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    st.caption("ASR liczony na próbach adwersarialnych; UAER jako wykonane nieautoryzowane działania / zaproponowane nieautoryzowane działania; FPR i LTCR na próbach benign. Brak mianownika oznacza „—”, nie zero.")
    chart_rows = []
    for config in configs:
        m = metric_summary(df[df.configuration == config])
        for metric in ["ASR", "UAER", "FPR", "LTCR"]:
            if m.get(metric) is not None:
                chart_rows.append({"Konfiguracja": CONFIG_LABELS[config], "Metryka": metric, "Wartość (%)": m[metric]})
    if chart_rows:
        st.plotly_chart(px.bar(pd.DataFrame(chart_rows), x="Konfiguracja", y="Wartość (%)", color="Metryka",
                               barmode="group", title="Porównanie metryk"), use_container_width=True)
    st.subheader("Opóźnienie")
    latency = df.dropna(subset=["latency_ms"])
    if not latency.empty:
        st.plotly_chart(px.box(latency, x="configuration", y="latency_ms", color="configuration",
                               points="all", title="Rozkład czasu wykonania (ms)"), use_container_width=True)
    st.subheader("Eksport tabeli metryk")
    st.download_button("Pobierz zestawienie CSV", pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig"),
                       "sentinel_metrics.csv", "text/csv")

def page_sources() -> None:
    st.title("🔖 Bibliografia i źródła")
    df = query_df("SELECT * FROM sources ORDER BY year DESC, title")
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    with st.form("add_source"):
        key = st.text_input("Klucz cytowania (np. author2024)")
        title = st.text_input("Tytuł publikacji")
        authors = st.text_input("Autorzy")
        year = st.text_input("Rok")
        doi = st.text_input("DOI / URL")
        chapter = st.text_input("Powiązany rozdział")
        notes = st.text_area("Notatki bibliograficzne")
        save = st.form_submit_button("Dodaj źródło")
    if save:
        if not title.strip():
            st.error("Tytuł publikacji jest wymagany.")
        else:
            with connect() as conn:
                conn.execute("""INSERT INTO sources(citation_key,title,authors,year,doi_url,linked_chapter,notes)
                VALUES(?,?,?,?,?,?,?)""", (key, title, authors, year, doi, chapter, notes))
            st.success("Źródło dodane.")
            st.rerun()
    if not df.empty:
        st.download_button("Eksport bibliografii CSV", df.to_csv(index=False).encode("utf-8-sig"),
                           "bibliography.csv", "text/csv")

def page_export() -> None:
    st.title("⬇️ Eksport i kopia danych")
    with connect() as conn:
        tables = ["chapters", "scenarios", "runs", "sources"]
        for table in tables:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            st.download_button(f"Pobierz {table}.csv", df.to_csv(index=False).encode("utf-8-sig"),
                               f"{table}.csv", "text/csv", key=f"export_{table}")
        st.download_button("Pobierz kopię bazy SQLite", DB_PATH.read_bytes(),
                           "sentinel_research_backup.sqlite", "application/octet-stream")

def main() -> None:
    init_db()
    with st.sidebar:
        st.title("Sentinel Research")
        page = st.radio("Nawigacja", ["Pulpit", "Dokumentacja", "Scenariusze", "Próby", "Analiza", "Bibliografia", "Eksport"])
        st.divider()
        st.caption("Dane przechowywane lokalnie w pliku sentinel_research.db.")
    pages = {
        "Pulpit": dashboard,
        "Dokumentacja": page_chapters,
        "Scenariusze": page_scenarios,
        "Próby": page_runs,
        "Analiza": page_analysis,
        "Bibliografia": page_sources,
        "Eksport": page_export,
    }
    pages[page]()

if __name__ == "__main__":
    main()
