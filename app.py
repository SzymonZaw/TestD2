from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from log_importer import LogValidationError, parse_experiment_logs
from sentinel_core import DEFAULT_ALLOWED_ACTIONS, evaluate_proposal
from statistical_analysis import describe_binary
from openai_planner import OpenAIPlanner
from api_usage import ApiUsageLedger
from playwright_runner import run_browser_agent

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
    page_title="Sentinel AI Web Shield",
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
        # Safe schema migration for databases created by earlier app versions.
        run_columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()}
        if "external_id" not in run_columns:
            conn.execute("ALTER TABLE runs ADD COLUMN external_id TEXT DEFAULT ''")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_external_id ON runs(external_id) WHERE external_id IS NOT NULL AND external_id != ''")
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
    st.subheader("Przedziały ufności 95% dla metryk binarnych")
    ci_rows = []
    for config in configs:
        part = df[df.configuration == config]
        attack = part[part.category == "adversarial"]
        benign_part = part[part.category == "benign"]
        proposed_total = int(attack["unauthorized_proposed"].sum())
        executed_total = int(attack["unauthorized_executed"].sum())
        metrics_ci = [
            ("ASR", int(attack["attack_success"].sum()), len(attack)),
            ("UAER", executed_total, proposed_total),
            ("FPR", int(benign_part["benign_flagged"].sum()), len(benign_part)),
            ("LTCR", int(benign_part["task_success"].sum()), len(benign_part)),
        ]
        for metric_name, successes, trials in metrics_ci:
            summary = describe_binary(successes, trials)
            ci_rows.append({
                "Konfiguracja": CONFIG_LABELS[config], "Metryka": metric_name,
                "Sukcesy / mianownik": f"{successes}/{trials}",
                "Wartość (%)": round(summary["rate_pct"], 2) if summary["rate_pct"] is not None else "—",
                "Dolna granica 95% (%)": round(summary["ci95_low_pct"], 2) if summary["ci95_low_pct"] is not None else "—",
                "Górna granica 95% (%)": round(summary["ci95_high_pct"], 2) if summary["ci95_high_pct"] is not None else "—",
            })
    st.dataframe(pd.DataFrame(ci_rows), use_container_width=True, hide_index=True)
    st.caption("Przedziały Wilsona dla proporcji; UAER używa liczby działań jako mianownika, pozostałe metryki — liczby prób. Są to przedziały opisowe; nie zastępują testów porównawczych ani uwzględnienia zależności między próbami.")
    st.subheader("Opóźnienie i narzut czasowy")
    latency = df.dropna(subset=["latency_ms"])
    if not latency.empty:
        st.plotly_chart(px.box(latency, x="configuration", y="latency_ms", color="configuration",
                               points="all", title="Rozkład czasu wykonania (ms)"), use_container_width=True)
    overhead = df.dropna(subset=["latency_ms", "baseline_latency_ms"]).copy()
    overhead = overhead[overhead["baseline_latency_ms"] > 0]
    if not overhead.empty:
        overhead["overhead_pct"] = (
            (overhead["latency_ms"] - overhead["baseline_latency_ms"])
            / overhead["baseline_latency_ms"] * 100
        )
        overhead_summary = overhead.groupby("configuration")["overhead_pct"].agg(
            ["count", "mean", "median", "std"]
        ).reset_index()
        overhead_summary["Konfiguracja"] = overhead_summary["configuration"].map(CONFIG_LABELS)
        st.dataframe(overhead_summary[["Konfiguracja", "count", "mean", "median", "std"]].rename(
            columns={"count": "Liczba pomiarów", "mean": "Średni narzut (%)",
                     "median": "Mediana narzutu (%)", "std": "Odchylenie standardowe"}
        ), use_container_width=True, hide_index=True)
        st.plotly_chart(px.box(overhead, x="configuration", y="overhead_pct",
            color="configuration", points="all",
            title="Narzut czasowy względem pomiaru bazowego (%)"), use_container_width=True)
    else:
        st.caption("Narzut czasowy nie jest liczony: uzupełnij dodatni czas bazowy dla pomiarów.")
    st.subheader("Eksport tabeli metryk")
    st.download_button("Pobierz zestawienie CSV", pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig"),
                       "sentinel_metrics.csv", "text/csv")

def page_log_import() -> None:
    st.title("📥 Import logów agenta (JSON / JSONL)")
    st.caption("Import wymaga uprzednio zdefiniowanych scenariuszy. Każdy rekord jest walidowany przed zapisem.")
    st.markdown("Minimalny rekord JSON:")
    st.code("""{
  "external_id": "run-0001",
  "scenario_key": "ADV-001",
  "configuration": "combined",
  "trial_no": 1,
  "category": "adversarial",
  "attack_success": false,
  "unauthorized_proposed": 1,
  "unauthorized_executed": 0,
  "benign_flagged": false,
  "task_success": false,
  "latency_ms": 125.4,
  "baseline_latency_ms": 98.2,
  "notes": "opcjonalne"
}""", language="json")
    uploaded = st.file_uploader("Wybierz plik .json lub .jsonl", type=["json", "jsonl"])
    if uploaded is not None:
        try:
            records = parse_experiment_logs(uploaded.getvalue().decode("utf-8-sig"), uploaded.name)
            st.success(f"Walidacja poprawna: {len(records)} rekordów.")
            st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True)
            if st.button("Importuj poprawne rekordy", type="primary"):
                inserted, skipped, errors = 0, 0, []
                with connect() as conn:
                    for index, record in enumerate(records, start=1):
                        scenario = conn.execute(
                            "SELECT id, category FROM scenarios WHERE scenario_key=?",
                            (record["scenario_key"],)
                        ).fetchone()
                        if scenario is None:
                            errors.append(f"Rekord {index}: nie znaleziono scenariusza {record['scenario_key']}.")
                            continue
                        if scenario["category"] != record["category"]:
                            errors.append(f"Rekord {index}: kategoria nie zgadza się ze scenariuszem {record['scenario_key']}.")
                            continue
                        external_id = record.get("external_id", "").strip()
                        if external_id and conn.execute("SELECT 1 FROM runs WHERE external_id=?", (external_id,)).fetchone():
                            skipped += 1
                            continue
                        conn.execute("""INSERT INTO runs(
                            scenario_id,configuration,trial_no,attack_success,unauthorized_proposed,
                            unauthorized_executed,benign_flagged,task_success,latency_ms,
                            baseline_latency_ms,notes,recorded_at,external_id
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                            int(scenario["id"]), record["configuration"], record["trial_no"],
                            record["attack_success"], record["unauthorized_proposed"],
                            record["unauthorized_executed"], record["benign_flagged"],
                            record["task_success"], record.get("latency_ms"),
                            record.get("baseline_latency_ms"), record.get("notes", ""),
                            datetime.now().isoformat(timespec="seconds"), external_id
                        ))
                        inserted += 1
                st.success(f"Zaimportowano: {inserted}; pominięto duplikaty: {skipped}.")
                if errors:
                    st.warning("Pominięte rekordy wymagające poprawy:\n" + "\n".join(errors))
                if inserted:
                    st.rerun()
        except (UnicodeDecodeError, LogValidationError) as exc:
            st.error(f"Nie udało się zaimportować pliku: {exc}")


def page_shield_prototype() -> None:
    st.title("🛡️ Sentinel — laboratorium prototypu")
    st.warning("To deterministyczny prototyp badawczy oparty na jawnych regułach. Nie jest kompletnym detektorem prompt injection ani samodzielną granicą bezpieczeństwa.")
    content = st.text_area("Tekst pobrany ze strony internetowej", height=180,
        placeholder="Wklej treść strony do analizy...")
    action = st.selectbox("Proponowane działanie agenta", [
        "read_page", "extract_text", "take_screenshot", "send_email",
        "submit_form", "download_file", "delete_file", "run_shell"
    ])
    if st.button("Oceń treść i działanie"):
        result = evaluate_proposal(content, action, DEFAULT_ALLOWED_ACTIONS)
        left, right = st.columns(2)
        with left:
            st.subheader("Analiza treści")
            st.metric("Wynik ryzyka", f"{result['content']['risk_score']}/100")
            st.write("Podejrzana treść:", "Tak" if result["content"]["suspicious"] else "Nie wykryto skonfigurowanych sygnałów")
            st.write(result["content"]["explanation"])
        with right:
            st.subheader("Autoryzacja działania")
            st.write("Decyzja:", "DOZWOLONE" if result["action"]["allowed"] else "ZABLOKOWANE")
            st.write("Powód:", result["action"]["reason"])
        st.info("Ocena treści i autoryzacja działania są niezależne. Brak wykrytego sygnału w treści nie nadaje agentowi dodatkowych uprawnień.")



def get_api_ledger() -> ApiUsageLedger:
    return ApiUsageLedger(APP_DIR / "sentinel_api_usage.sqlite3")


def daily_api_limit() -> int:
    try:
        return max(1, min(1000, int(os.getenv("SENTINEL_DAILY_API_CALL_LIMIT", "50"))))
    except ValueError:
        return 50


def page_browser_agent() -> None:
    st.title("🤖 Agent przeglądarkowy")
    st.warning(
        "Uruchomienie agenta wysyła zadanie i treść obserwowanych stron do OpenAI. "
        "Każde wywołanie API może generować koszt. Agent ma wyłącznie akcje navigate/read_page."
    )
    if not os.getenv("OPENAI_API_KEY"):
        st.error("Brak OPENAI_API_KEY w środowisku. Agent AI jest niedostępny.")
        return

    model = os.getenv("SENTINEL_OPENAI_MODEL", "gpt-4.1-mini")
    ledger = get_api_ledger()
    daily_limit = daily_api_limit()
    daily_usage = ledger.snapshot()
    st.success(f"Klucz API wykryty — model: {model}. Wartość klucza nie jest wyświetlana.")
    st.metric("Dzisiejsze zapytania OpenAI (UTC)", f"{daily_usage['request_count']} / {daily_limit}")
    st.caption(f"Tokeny dzisiaj: {daily_usage['total_tokens']} · Limit jest wspólny dla wszystkich sesji aplikacji.")
    with st.form("browser_agent_run"):
        task = st.text_area("Zadanie dla agenta", placeholder="Otwórz stronę i przeczytaj jej publiczną zawartość.", max_chars=1000)
        origins_text = st.text_input("Dozwolone originy (oddziel przecinkami)", placeholder="https://example.com")
        max_calls = st.slider("Maksymalna liczba zapytań do OpenAI w tym uruchomieniu", min_value=1, max_value=8, value=3)
        headless = st.checkbox("Przeglądarka w tle (headless)", value=True)
        submitted = st.form_submit_button("Uruchom agenta — użyje API", type="primary")

    if submitted:
        origins = [item.strip() for item in origins_text.split(",") if item.strip()]
        if not task.strip():
            st.error("Wpisz zadanie agenta.")
            return
        if not origins:
            st.error("Podaj co najmniej jeden dozwolony origin.")
            return

        st.session_state["api_requests_before_run"] = st.session_state.get("api_requests", 0)
        st.session_state["api_tokens_before_run"] = st.session_state.get("api_tokens", 0)
        recorded_prompt = 0
        recorded_completion = 0

        def record_usage(usage: dict[str, int | str]) -> None:
            nonlocal recorded_prompt, recorded_completion
            prompt_delta = int(usage["prompt_tokens"]) - recorded_prompt
            completion_delta = int(usage["completion_tokens"]) - recorded_completion
            if prompt_delta > 0 or completion_delta > 0:
                ledger.record_tokens(prompt_delta, completion_delta)
            recorded_prompt = int(usage["prompt_tokens"])
            recorded_completion = int(usage["completion_tokens"])
            st.session_state["api_requests"] = st.session_state["api_requests_before_run"] + usage["request_count"]
            st.session_state["api_tokens"] = st.session_state["api_tokens_before_run"] + usage["total_tokens"]

        planner = None
        try:
            planner = OpenAIPlanner(
                task, model=model, max_api_calls=max_calls,
                usage_callback=record_usage,
                request_guard=lambda: ledger.reserve_request(daily_limit),
            )
            with st.spinner("Agent pracuje. Zapytania do OpenAI są wykonywane..."):
                result = run_browser_agent("streamlit-agent", planner, origins, headless=headless, max_steps=max_calls)
            st.session_state["last_agent_usage"] = planner.usage
            st.subheader("Wynik uruchomienia")
            st.write(f"Status: **{result.stopped_reason}**")
            if planner.last_error:
                st.error(planner.last_error)
            st.write(f"Zadanie zakończone: **{'tak' if result.completed else 'nie'}**")
            st.write(f"Liczba kroków: **{len(result.observations)}**")
            st.json(planner.usage)
            for index, observation in enumerate(result.observations, start=1):
                with st.expander(f"Krok {index}: {observation.action} — {observation.target_url}"):
                    st.write("Dozwolone:", observation.result.allowed)
                    st.write("Wykonane:", observation.result.executed)
                    st.write("Powód:", observation.result.reason)
                    output = observation.result.output
                    st.text(str(getattr(output, "value", output))[:4000])
        except Exception as exc:
            st.error(f"Agent zatrzymany: {type(exc).__name__}: {exc}")
            if planner is not None:
                st.session_state["last_agent_usage"] = planner.usage
                st.json(planner.usage)


def page_api_status() -> None:
    st.title("🔐 Status i kontrola API")
    configured = bool(os.getenv("OPENAI_API_KEY"))
    st.metric("Klucz OPENAI_API_KEY", "Wykryty" if configured else "Brak")
    st.write("Model:", os.getenv("SENTINEL_OPENAI_MODEL", "gpt-4.1-mini"))
    ledger = get_api_ledger()
    daily = ledger.snapshot()
    st.write("Dzisiejsze zapytania (UTC):", f"{daily['request_count']} / {daily_api_limit()}")
    st.write("Dzisiejsze tokeny:", daily["total_tokens"])
    st.write("W tym tokeny wejściowe:", daily["prompt_tokens"])
    st.write("W tym tokeny wyjściowe:", daily["completion_tokens"])
    st.write("Zapytania w bieżącej sesji UI:", st.session_state.get("api_requests", 0))
    last = st.session_state.get("last_agent_usage")
    if last:
        st.subheader("Ostatnie uruchomienie")
        st.json(last)
    st.info(
        "Klucz jest pobierany ze zmiennej środowiskowej i nigdy nie jest pokazywany w interfejsie. "
        "Wywołania API następują dopiero po ręcznym uruchomieniu agenta. "
        f"Każde uruchomienie ma limit zapytań, a wspólny dzienny limit wynosi {daily_api_limit()} żądań. "
        "Limit odpowiedzi to 500 tokenów na jedno zapytanie."
    )
    st.warning(
        "Aplikacja pokazuje liczbę żądań i tokeny raportowane przez API, ale nie wylicza ceny — "
        "stawki zależą od modelu i mogą się zmieniać. Rzeczywisty koszt sprawdzaj w panelu rozliczeń OpenAI."
    )


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
    st.session_state.setdefault("api_requests", 0)
    st.session_state.setdefault("api_tokens", 0)
    daily = get_api_ledger().snapshot()
    with st.sidebar:
        st.title("🛡️ Sentinel AI Web Shield")
        configured = bool(os.getenv("OPENAI_API_KEY"))
        st.markdown(f"**OpenAI API:** {'🟢 skonfigurowane' if configured else '🔴 brak klucza'}")
        st.caption(f"Dziś: {daily['request_count']} / {daily_api_limit()} żądań · {daily['total_tokens']} tokenów")
        st.divider()
        page = st.radio("Nawigacja", ["Ochrona treści", "Agent przeglądarkowy", "Status i kontrola API"])
    pages = {
        "Ochrona treści": page_shield_prototype,
        "Agent przeglądarkowy": page_browser_agent,
        "Status i kontrola API": page_api_status,
    }
    pages[page]()

if __name__ == "__main__":
    main()
