# Sentinel AI Web Shield — Research Manager

Lokalna aplikacja Streamlit do prowadzenia dokumentacji doktoratu oraz ewidencji scenariuszy i prób eksperymentalnych związanych z badaniem ochrony agentów webowych przed indirect prompt injection.

## Funkcje

- Rejestr rozdziałów i podrozdziałów doktoratu wraz ze statusem i notatkami.
- Katalog scenariuszy adwersarialnych i poprawnych (benign).
- Rejestr prób dla czterech konfiguracji: baseline, content-only, policy-only i combined.
- Obliczanie ASR, UAER, FPR i LTCR na podstawie zapisanych obserwacji.
- Wykresy porównawcze i analiza czasu wykonania.
- Katalog bibliografii oraz eksport danych do CSV i kopii SQLite.

## Uruchomienie w PyCharm

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/SzymonZaw/TestD2.git
   cd TestD2
   ```

2. Otwórz katalog projektu w PyCharm i utwórz środowisko wirtualne (Python 3.10 lub nowszy).
3. W terminalu PyCharm zainstaluj zależności:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Uruchom aplikację:

   ```bash
   streamlit run app.py
   ```

5. Aplikacja otworzy się lokalnie w przeglądarce. Baza `sentinel_research.db` zostanie utworzona automatycznie w katalogu projektu.

## Definicje metryk

- **ASR** = liczba prób adwersarialnych zakończonych sukcesem ataku / liczba zarejestrowanych prób adwersarialnych.
- **UAER** = liczba wykonanych nieautoryzowanych działań / liczba zaproponowanych nieautoryzowanych działań. Próby bez zaproponowanego działania nie zwiększają mianownika.
- **FPR** = liczba poprawnych prób błędnie oznaczonych lub zablokowanych / liczba zarejestrowanych prób benign.
- **LTCR** = liczba poprawnych zadań ukończonych pomyślnie / liczba zarejestrowanych prób benign.

Metryki są prezentowane jako procenty. Jeżeli mianownik nie istnieje, aplikacja pokazuje „—”, a nie 0%.

## Ważne uwagi metodologiczne

- Aplikacja jest narzędziem do dokumentowania i analizy badań. Sama nie implementuje mechanizmów Sentinel AI Web Shield i nie wykonuje działań w przeglądarce.
- Nie dodawaj do repozytorium prawdziwych haseł, tokenów, ciasteczek sesyjnych ani danych wrażliwych.
- Nie wpisuj danych demonstracyjnych jako rzeczywistych wyników. Aplikacja rozpoczyna pracę z pustą bazą prób i oblicza metryki dopiero po wprowadzeniu obserwacji.
- Jednostką ASR/FPR/LTCR jest próba eksperymentalna. UAER jest metryką działania i korzysta z liczników działań; w pracy należy jasno opisać oba poziomy agregacji.
- Przed analizą statystyczną sprawdź spójność scenariuszy, numerów powtórzeń i konfiguracji. Eksport CSV można wykorzystać do dalszej analizy np. w Pythonie/R.

## Pliki

- `app.py` — interfejs aplikacji, baza SQLite, rejestracja danych, metryki, wykresy i eksport.
- `requirements.txt` — zależności Pythona.
- `sentinel_research.db` — lokalna baza tworzona przy pierwszym uruchomieniu (nie jest wersjonowana).
