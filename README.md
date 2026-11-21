# Sentinel AI Web Shield — Research Manager

Lokalna aplikacja Streamlit do dokumentowania doktoratu, katalogowania scenariuszy i rejestrowania prób eksperymentalnych dotyczących ochrony agentów webowych przed indirect prompt injection. Repozytorium zawiera również wczesny, deterministyczny prototyp mechanizmów Sentinel.

## Funkcje aplikacji

- Dokumentacja rozdziałów i podrozdziałów doktoratu.
- Katalog scenariuszy adwersarialnych i poprawnych (benign).
- Rejestr prób dla czterech konfiguracji: baseline, content-only, policy-only i combined.
- Import logów JSON oraz JSONL, walidacja rekordów i pomijanie powtórnego importu rekordów z tym samym `external_id`.
- Obliczanie ASR, UAER, FPR i LTCR, przedziały Wilsona 95% oraz analizę czasu i względnego narzutu względem pomiaru bazowego.
- Katalog bibliografii, eksport CSV i kopia bazy SQLite.
- Laboratorium prototypu: ocena tekstu strony i niezależna kontrola proponowanej akcji.

## Uruchomienie w PyCharm

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/SzymonZaw/TestD2.git
   cd TestD2
   ```

2. Otwórz katalog projektu w PyCharm i utwórz środowisko wirtualne (Python 3.10 lub nowszy).
3. Zainstaluj zależności:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Uruchom aplikację:

   ```bash
   streamlit run app.py
   ```

Baza `sentinel_research.db` zostanie utworzona automatycznie w katalogu projektu.

## Format importu logów

Importer przyjmuje pojedynczy obiekt JSON, tablicę obiektów JSON lub JSONL (jeden obiekt na linię). Wymagane pola:

- `scenario_key` — identyfikator scenariusza istniejącego w aplikacji,
- `configuration` — `baseline`, `content_only`, `policy_only` lub `combined`,
- `trial_no` — numer próby (liczba całkowita od 1),
- `category` — `adversarial` albo `benign`.

Pola opcjonalne: `external_id`, `attack_success`, `unauthorized_proposed`, `unauthorized_executed`, `benign_flagged`, `task_success`, `latency_ms`, `baseline_latency_ms`, `notes`. Wartości logiczne należy przekazywać jako JSON `true`/`false`. Dla ochrony przed duplikatami nadaj każdemu zdarzeniu stabilny, unikalny `external_id`.

Przykład:

```json
{
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
}
```

Scenariusz o podanym kluczu musi wcześniej istnieć w katalogu, a jego kategoria musi zgadzać się z kategorią rekordu.

## Śledzenie pochodzenia danych (Provenance Tracking)

- `provenance.py` dostarcza niezmienne etykiety `TRUSTED` i `UNTRUSTED` oraz obiekt `TrackedText` przechowujący źródło i historię transformacji.
- `TrackedText.from_web(...)` zawsze oznacza tekst pobrany ze strony jako `UNTRUSTED`.
- Transformacje zachowują etykietę zaufania. Łączenie danych zaufanych i niezaufanych powoduje oznaczenie całego wyniku jako `UNTRUSTED`.
- Dostępna jest operacja obniżenia zaufania (`mark_untrusted`), ale nie ma metody podnoszącej zaufanie. `from_trusted_source` wolno wywoływać wyłącznie na zaufanej granicy aplikacji.
- To warstwa metadanych dla przepływu danych, a nie kompletne IFC. Dopóki wszystkie źródła danych i transformacje agenta nie korzystają z tych obiektów, oznaczenia nie są automatycznie egzekwowane w całej aplikacji.

## Information Flow Control (IFC)

- `ifc.py` kontroluje przepływ pól jawnie oznaczonych jako niezaufane do skonfigurowanych wrażliwych operacji.
- `ActionRequest.untrusted_fields` przechowuje nazwy niezaufanych pól najwyższego poziomu argumentów. Każde pole musi istnieć w argumentach żądania.
- Oznaczenia taint są częścią fingerprintu żądania. Zmiana etykiet po przygotowaniu zgody unieważnia zgodę.
- Niezaufane dane nie mogą trafić do wrażliwego sinka bez dokładnej zgody. Handler nie jest wywoływany przy odmowie.
- To początkowa, jawna warstwa IFC. Integracja musi poprawnie oznaczać wszystkie pola pochodzące z danych WWW; brak etykiety nie dowodzi zaufania. Kontrola nie obejmuje jeszcze automatycznego śledzenia pochodzenia w całym runtime agenta.

## Adapter przeglądarki Playwright

- `browser_adapter.py` udostępnia wyłącznie dwie operacje: `navigate` i `read_page`. Nie udostępnia kliknięć, wypełniania pól, wysyłania formularzy, pobierania plików ani wykonywania JavaScript.
- Adapter przyjmuje istniejący obiekt `Page` z synchronicznego Playwright i listę dozwolonych originów. Instaluje interceptor `page.route("**/*", ...)`, który przepuszcza wyłącznie żądania HTTP(S) do tych originów; pozostałe żądania, w tym żądania do obcych zasobów i przekierowania, są blokowane.
- Tę samą listę originów należy przekazać do `TaskContract.allowed_origins`. Handlerów adaptera nie należy wywoływać bezpośrednio — przekazuje się je do `ExecutionGateway`.
- `read_page` zwraca `TrackedText.from_web(...)`, więc tekst strony jest oznaczony jako `UNTRUSTED`. Przekazując go do kolejnego działania, należy używać `ActionRequest.from_tracked_arguments(...)`, aby zachować oznaczenie.
- Playwright jest opcjonalną zależnością. Instalacja: `python -m pip install playwright`, a następnie `python -m playwright install chromium`. Sam pakiet nie jest wymagany do uruchamiania testów jednostkowych adaptera (testy korzystają z atrap).
## Pętla agenta

- `agent_runtime.py` udostępnia ograniczoną pętlę planowania: planner dostaje wyłącznie historię obserwacji i zwraca pojedynczą propozycję `AgentProposal`. Każda propozycja jest konwertowana na `ActionRequest.from_tracked_arguments(...)` i wykonywana wyłącznie przez `ExecutionGateway`.
- Runtime nie otrzymuje obiektu przeglądarki ani handlerów. Nie ma alternatywnego API do kliknięć, wysyłania formularzy czy uruchamiania kodu. W aktualnym kontrakcie runnera dozwolone są tylko `navigate` i `read_page`.
- Pętla ma limit kroków (`max_steps`), kończy się po odmowie Gateway i zwraca historię wyników. Dane `TrackedText` z obserwacji zachowują etykietę `UNTRUSTED`, także gdy planner przekaże je jako argument kolejnej akcji.
- `playwright_runner.py` uruchamia Chromium, tworzy kontekst z `service_workers="block"`, konfiguruje adapter, Gateway i runtime, a następnie zamyka kontekst oraz przeglądarkę. Obiekty `Page` i browser nie są zwracane plannerowi.
- Przykład prostego planera (bez modelu językowego):

```python
from agent_runtime import AgentProposal
from playwright_runner import run_browser_agent

def planner(history):
    if not history:
        return AgentProposal("navigate", "https://example.com")
    if len(history) == 1:
        return AgentProposal("read_page", "https://example.com")
    print(history[-1].result.output.value)
    return None

result = run_browser_agent(
    task_id="demo",
    planner=planner,
    allowed_origins={"https://example.com"},
    headless=True,
    max_steps=4,
)
print(result.stopped_reason, result.completed)
```

Instalacja: `python -m pip install playwright`, a następnie `python -m playwright install chromium`. Zależność jest opcjonalna — core i testy atrap nie wymagają uruchamiania przeglądarki.

Runtime nie implementuje samodzielnie LLM ani uwierzytelniania zgód. Planner może być podłączony do modelu przez adapter aplikacyjny, ale jego propozycje nie uzyskują uprawnień: każda przechodzi przez Gateway. Obecny runner celowo nie obsługuje operacji zmieniających stan strony lub konta. To prototyp badawczy, nie izolacja procesu ani gotowe zabezpieczenie produkcyjne.

## Prototyp Sentinel — zakres i ograniczenia

- `sentinel_core.py` zawiera jawne reguły heurystyczne do wykrywania wybranych wzorców instrukcji, takich jak próby nadpisania instrukcji, ujawnienia promptu, eksfiltracji sekretów czy manipulacji narzędziami.
- `authorize_action` stosuje niezależną listę dozwolonych działań; nieznane akcje są domyślnie odrzucane.
- `policy.py` wiąże żądanie z identyfikatorem zadania, dozwolonym originem i odciskiem dokładnych argumentów. Działania wrażliwe (m.in. wysyłanie wiadomości, submit formularza, usuwanie, zakup, upload i uruchamianie powłoki) wymagają osobnej zgody nawet wtedy, gdy nazwa akcji znajduje się na allowliście.
- `execution_gateway.py` jest punktem egzekwowania polityki: uruchamia zarejestrowany handler dopiero po pozytywnej decyzji. Handler otrzymuje kopię argumentów objętych odciskiem żądania; odrzucone żądania nie wywołują handlera.
- Ocena treści nie nadaje uprawnień. Nawet jeśli tekst nie uruchomi reguły detekcyjnej, akcja nadal przechodzi osobną kontrolę polityki.
- Reguły są celowo przejrzyste i stanowią punkt odniesienia do eksperymentów. Mogą generować fałszywe alarmy i przeoczenia. Nie są semantycznym detektorem, sandboxem, mechanizmem uwierzytelniania ani kompletną ochroną przeglądarki.
- Gateway pozostaje adapterem badawczym, ale repozytorium zawiera teraz ograniczony adapter synchronicznego Playwright opisany poniżej. Nie jest to jeszcze integracja z autonomicznym agentem.
- `ApprovalGrant` jest obecnie obiektem danych, a nie podpisanym tokenem ani dowodem uwierzytelnienia. W produkcji musi być tworzony wyłącznie przez zaufany komponent interfejsu po uwierzytelnieniu użytkownika. Samo utworzenie obiektu w Pythonie nie stanowi bezpiecznego procesu akceptacji.

## Definicje metryk

- **ASR** = udane ataki / próby adwersarialne.
- **UAER** = wykonane nieautoryzowane działania / zaproponowane nieautoryzowane działania.
- **FPR** = poprawne próby błędnie oznaczone lub zablokowane / próby benign.
- **LTCR** = poprawne zadania ukończone pomyślnie / próby benign.

ASR, FPR i LTCR mają jednostkę próby. UAER ma jednostkę działania. Przedziały Wilsona są prezentowane dla proporcji; nie zastępują testów porównawczych, analizy mocy ani modelowania zależności między próbami.

## Testy

Repozytorium ma również workflow GitHub Actions, który przy push i pull request wykonuje kompilację kontrolną oraz testy jednostkowe.

Uruchom testy jednostkowe:

```bash
python -m unittest discover -s tests -v
```

Testy gatewaya używają atrap handlerów, aby potwierdzić, że odrzucone operacje nie wywołują żadnego wykonawcy. Przykładową integrację należy budować przez przekazanie jawnego słownika handlerów do `ExecutionGateway`; nie należy udostępniać agentowi alternatywnej ścieżki bez kontroli polityki.

## Ważne uwagi badawcze i bezpieczeństwa

- Aplikacja rozpoczyna pracę bez danych eksperymentalnych; nie generuje wyników badań.
- Nie dodawaj do repozytorium haseł, tokenów, ciasteczek sesyjnych ani innych danych wrażliwych.
- Przed wnioskowaniem o skuteczności zabezpieczeń przeprowadź eksperymenty na kontrolowanym benchmarku, z ustalonymi etykietami, powtórzeniami i procedurą oceny.
- Nie traktuj wyników heurystyk prototypu jako dowodu odporności na indirect prompt injection.
