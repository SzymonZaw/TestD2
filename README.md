# Sentinel AI Web Shield — Research Manager

Lokalna aplikacja Streamlit do dokumentowania doktoratu, katalogowania scenariuszy i rejestrowania prób eksperymentalnych dotyczących ochrony agentów webowych przed indirect prompt injection. Repozytorium zawiera również wczesny, deterministyczny prototyp mechanizmów Sentinel.

## Funkcje aplikacji

- Dokumentacja rozdziałów i podrozdziałów doktoratu.
- Katalog scenariuszy adwersarialnych i poprawnych (benign).
- Rejestr prób dla czterech konfiguracji: baseline, content-only, policy-only i combined.
- Import logów JSON oraz JSONL, walidacja rekordów i pomijanie powtórnego importu rekordów z tym samym `external_id`.
- Obliczanie ASR, UAER, FPR i LTCR, wykresy i przedziały Wilsona 95%.
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

## Prototyp Sentinel — zakres i ograniczenia

- `sentinel_core.py` zawiera jawne reguły heurystyczne do wykrywania wybranych wzorców instrukcji, takich jak próby nadpisania instrukcji, ujawnienia promptu, eksfiltracji sekretów czy manipulacji narzędziami.
- `authorize_action` stosuje niezależną listę dozwolonych działań; nieznane akcje są domyślnie odrzucane.
- Ocena treści nie nadaje uprawnień. Nawet jeśli tekst nie uruchomi reguły detekcyjnej, akcja nadal przechodzi osobną kontrolę polityki.
- Reguły są celowo przejrzyste i stanowią punkt odniesienia do eksperymentów. Mogą generować fałszywe alarmy i przeoczenia. Nie są semantycznym detektorem, sandboxem, mechanizmem uwierzytelniania ani kompletną ochroną przeglądarki.
- Prototyp nie jest jeszcze podłączony do rzeczywistego agenta ani do przeglądarki. Nie wykonuje narzędzi ani operacji sieciowych.

## Definicje metryk

- **ASR** = udane ataki / próby adwersarialne.
- **UAER** = wykonane nieautoryzowane działania / zaproponowane nieautoryzowane działania.
- **FPR** = poprawne próby błędnie oznaczone lub zablokowane / próby benign.
- **LTCR** = poprawne zadania ukończone pomyślnie / próby benign.

ASR, FPR i LTCR mają jednostkę próby. UAER ma jednostkę działania. Przedziały Wilsona są prezentowane dla proporcji; nie zastępują testów porównawczych, analizy mocy ani modelowania zależności między próbami.

## Testy

Uruchom testy jednostkowe:

```bash
python -m unittest discover -s tests -v
```

## Ważne uwagi badawcze i bezpieczeństwa

- Aplikacja rozpoczyna pracę bez danych eksperymentalnych; nie generuje wyników badań.
- Nie dodawaj do repozytorium haseł, tokenów, ciasteczek sesyjnych ani innych danych wrażliwych.
- Przed wnioskowaniem o skuteczności zabezpieczeń przeprowadź eksperymenty na kontrolowanym benchmarku, z ustalonymi etykietami, powtórzeniami i procedurą oceny.
- Nie traktuj wyników heurystyk prototypu jako dowodu odporności na indirect prompt injection.
