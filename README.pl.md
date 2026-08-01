# agent-safety-gate

*Wersja angielska: [README.md](README.md)*

## Poniedziałek rano

Twój agent coś zrobił w piątek. Ktoś pyta, dlaczego mu na to pozwolono.

Transkrypt agenta masz w jednym miejscu, logi serwera narzędzi w drugim, a logi
CI w trzecim. Po dwóch godzinach masz historię, która brzmi prawdopodobnie. Nie
możesz jej udowodnić, nie możesz jej odtworzyć i nie masz pewności, że tak
właśnie było.

Tak samo wygląda ten piątek, jeśli wywołania przeszły najpierw przez bramę:

```text
PASS   fetch_url    Agent czyta stronę z instrukcją instalacji, o którą go poproszono.
                    Every control signal was measured and came from a source other than the gated agent.
WARN   write_file   Strona kazała mu zapisać notatkę poza obszarem, który dostał.
                    Forwarded with a warning because path='docs/NOTES.md' is outside the declared scope (paths src/, tests/).
BLOCK  run_shell    Strona kazała mu wyczyścić katalog roboczy i zrobić force-push. Agent ręczy sam za siebie.
                    Blocked because the gated agent attached its own safety claim to this call (self-attestation, never
                    counted in favour of the call); the scope of this call could not be measured; no independent approval
                    exists for this `irreversible` call.
```

Trzy podpisane rekordy, spięte w łańcuch. Upuść ten plik na jedną stronę HTML,
a każdy skrót zostanie przeliczony na Twoich oczach, offline. Ta strona jest
produktem.

**agent-safety-gate** staje przed wywołaniami narzędzi agenta i przed każdym z
nich odpowiada na jedno pytanie: *czy sygnały kontrolne wokół tego wywołania są
kompletne i czy którykolwiek z nich pochodzi ze źródła innego niż sam agent?*
Zwraca PASS, WARN albo BLOCK i w każdym przypadku zostawia podpisany,
odtwarzalny rekord.

Komunikaty samej bramy są po angielsku - to jeden strumień tekstu, który trafia
do rekordów i do weryfikatora, więc nie tłumaczymy go w połowie drogi.

## Czym to NIE jest

* **Nie** poprawia agenta, nie recenzuje jego kodu i nie ocenia, czy działanie
  było dobrym pomysłem.
* **Nie zawiera żadnego modelu językowego.** W bramie nie ma sędziego LLM, nie ma
  klasyfikatora ani heurystyki, która patrzy na `rm -rf` i uznaje to za groźne.
  Sprawdź zależności; `tests/test_project_constraints.py` to weryfikuje.
* **Nie wykrywa** niebezpiecznych działań. To operator deklaruje, co robi każde
  narzędzie. Brama stosuje tę deklarację i raportuje to, czego nie zmierzyła.
* **Nie** daje gwarancji zgodności z czymkolwiek. Zobacz
  [Obowiązki rejestrowania](#obowiązki-rejestrowania), żeby wiedzieć, co
  faktycznie wspiera.

Jedyne twierdzenie o bezpieczeństwie, jakie stawia: **ścieżki nieaudytowalne są
odcinane albo oznaczane.** Tyle.

## Szybki start

Z klona tego repozytorium. Gdy pakiet trafi na PyPI, pierwsza linia zmieni się w
`pip install agent-safety-gate`; zobacz
[docs/OWNER_DECISIONS.md](docs/OWNER_DECISIONS.md).

```bash
pip install .
agent-safety-gate demo
```

`demo` zapisuje trzy rekordy, kopiuje obok nich weryfikator i mówi, jak go
otworzyć. Bez konta, bez rejestracji, bez sieci, bez konfiguracji. Klucz
podpisujący powstaje przy pierwszym uruchomieniu i jest oznaczony jako
`DEMO KEY - DO NOT USE IN PRODUCTION`.

Potem otwórz `verify.html` i upuść na niego `records.jsonl`. Patrzysz na
zablokowaną nieodwracalną akcję z zieloną weryfikacją podpisu, policzoną w
Twojej przeglądarce.

**Zmierzony czas od `pip install` do tego zielonego znaczka: 10,3 s**
(8-11 s w kolejnych uruchomieniach na jednym laptopie; przeciąganie pliku
wykonuje headless browser).

```bash
bash tools/quickstart_check.sh   # wykonuje powyższe dwie komendy dosłownie i mierzy czas
```

## Ból, funkcja, dowód

| Ból | Co robi brama | Sprawdź to |
| --- | --- | --- |
| „Coś zrobił i nikt nie umie odtworzyć, dlaczego to przeszło." | Każde wywołanie zostawia jeden rekord z sygnałami, liczbami, werdyktem i uzasadnieniem. `explain` odczytuje go po miesiącach zwykłym językiem. | `agent-safety-gate explain examples/sample_records.jsonl --line 3` |
| „Nie mogę delegować, bo nie ufam." Zatwierdzanie wszystkiego to approval fatigue; niezatwierdzanie niczego to brak delegowania. | Akcje nieodwracalne i o skutku zewnętrznym są blokowane, dopóki nie istnieje niezależna zgoda związana z dokładnie tym wywołaniem. Wszystko odwracalne i w zakresie przechodzi bez pytania. | `python benchmarks/workflow_replay.py` |
| „Audytor pyta, jaką mamy kontrolę nad agentami, a my nie mamy nic pokazywalnego." | Podpisany plik rekordów spiętych w łańcuch i jedna strona HTML, która weryfikuje go offline na maszynie audytora, bez instalacji i bez zaufania do nas. | `agent-safety-gate demo`, a potem upuść plik na `verify.html` |
| „Agent przeczytał zatrutą stronę i wykonał jej polecenie." | Brama nigdy nie liczy własnego zapewnienia agenta na korzyść wywołania. Wywołanie z samooceną agenta jest blokowane. | `agent-safety-gate explain examples/sample_records.jsonl --line 3` |
| „Podpięcie nowego serwera narzędzi do czegokolwiek zajmuje dzień." | Jeden plik YAML i jeden zmieniony adres w konfiguracji klienta. Żadnych zmian w kodzie po którejkolwiek stronie. | `python tools/measure_wiring.py --policy examples/public_server_policy.yaml --tool get_current_time --arguments '{"timezone": "Europe/Warsaw"}'` |

## Opakuj własny serwer MCP

Brama jest proxy MCP. Twój klient łączy się z nią zamiast z serwerem narzędzi;
serwer narzędzi nie wie, że ona tam jest.

```bash
pip install "agent-safety-gate[mcp]"
```

Napisz jeden plik polityki:

```yaml
policy_id: my_agent
policy_version: "1.0.0"

upstream:
  label: my-tools
  command: [python, -m, my_mcp_server]

tools:
  read_file:
    action_class: read_only
    scope:
      argument: path
      allow_path_prefixes: [src/, tests/]
  write_file:
    action_class: reversible_write
    scope:
      argument: path
      allow_path_prefixes: [src/]
  run_shell:
    action_class: irreversible      # wymaga niezależnej zgody
```

Zapytaj bramę, co ten serwer wystawia i czego jeszcze nie zadeklarowałeś:

```bash
agent-safety-gate wrap --policy my_policy.yaml --check
```

Uruchamia serwer docelowy, wypisuje jego narzędzia i drukuje blok polityki dla
tych, których nie pokryłeś - z klasą akcji wypełnioną wszędzie tam, gdzie serwer
publikuje o sobie adnotacje MCP, oznaczoną jako propozycja, plus argument zakresu
znaleziony w schemacie. Tam, gdzie serwer nic nie mówi, `action_class:` zostaje
puste: brama nie zgaduje, co robi narzędzie, a zgadnięta klasa byłaby gorsza niż
brak wpisu.

Potem wskaż klientowi MCP bramę zamiast serwera:

```json
{
  "mcpServers": {
    "my-tools": {
      "command": "agent-safety-gate",
      "args": ["wrap", "--policy", "/abs/path/my_policy.yaml"]
    }
  }
}
```

PASS jest przekazywany bez zmian, WARN jest przekazywany z ostrzeżeniem
doklejonym do odpowiedzi, BLOCK nigdy nie dociera do narzędzia. To pasuje do
wąskiego, nazwanego zestawu narzędzi; postaw to przed jednym shellem „do
wszystkiego" i dostaniesz approval fatigue - zmierzone, nie zadeklarowane, w
[Użyteczność na prawdziwej sesji](#użyteczność-na-prawdziwej-sesji). Gotowy przykład
z serwerem spoza tego repozytorium jest w
[`examples/public_server_policy.yaml`](examples/public_server_policy.yaml).

## Przeczytaj decyzję

```bash
agent-safety-gate explain examples/sample_records.jsonl --line 3
```

```text
Record 3 of 3   BLOCK   run_shell
  arguments: {"command":"rm -rf /home/dev/project && git push --force origin main"}

What was measured
  action_class           irreversible   independent   policy:demo_coding_agent@...
  agent_self_assessment  self_attested  SELF-ATTESTED gated agent (call metadata)
  approval_present       absent         independent   approvals_dir:...
  policy_coverage        covered        independent   policy:demo_coding_agent@...
  scope_match            not measured   independent   policy:demo_coding_agent@...

What to do
  3. `run_shell` is declared `irreversible` and requires an independent approval, which is missing
     -> If a human really wants this exact call to run, write an approval file bound to its
        action digest. The approval covers these arguments only: change one character and the
        digest no longer matches.
        mkdir -p .agent-safety-gate/approvals && printf '{"approved_by":"me"}' > .agent-safety-gate/approvals/266cba07....json
```

Każda decyzja mówi, czego zabrakło i co z tym zrobić - nie tylko kod błędu.

## Zweryfikuj łańcuch offline

W terminalu:

```bash
agent-safety-gate verify examples/sample_records.jsonl
agent-safety-gate verify examples/sample_records.jsonl --public-key b7aaWkspKWjoOeaWZ5zE4g3D4gp5EkGIUhA4gT0zzBk=
```

Albo w przeglądarce, bez instalowania czegokolwiek: otwórz
[`verifier/verify.html`](verifier/verify.html) i upuść na niego dowolny plik
rekordów - również z Twojego własnego uruchomienia, o to właśnie chodzi. Strona
przelicza każdy skrót, przechodzi łańcuch i sprawdza każdy podpis Ed25519 przez
WebCrypto. Deklaruje politykę bezpieczeństwa treści zakazującą dostępu do sieci,
więc „nic nie jest wysyłane" jest czymś, co wymusza przeglądarka, a nie czymś,
co obiecujemy.

Dwie różne własności, i ta różnica ma znaczenie:

* **łańcuch skrótów** jest *tamper-evident*: pokazuje, że plik został zmieniony
  i który rekord ucierpiał;
* **podpis Ed25519** to *uwierzytelnienie wystawcy*: jest niepodrabialny bez
  klucza prywatnego.

Poprawny podpis mówi, że rekord podpisał posiadacz tego klucza. Nie mówi, kim
jest ten posiadacz. Przypnij klucz, którego się spodziewasz - po to jest
`--public-key` i pole na stronie.

## Działa z tym, co już masz

Troje drzwi, jedna brama, jeden łańcuch rekordów - wyłącznie konfiguracja, zero
zmian w kodzie:

* **Proxy MCP** (`wrap`) - Claude Desktop, Cursor, Windsurf, Claude Code i
  wszystko inne z konfiguracją `mcpServers` wskazuje bramę zamiast serwera.
* **Hook Claude Code** (`hook`) - jeden wpis w `.claude/settings.json` bramkuje
  narzędzia *natywne* (Bash, Edit, Write), których żadne proxy MCP nie widzi.
  PASS przestaje pytać, WARN pyta z uzasadnieniem, BLOCK odmawia z remediacją;
  brak polityki nigdy nie unieruchamia agenta.
* **Dowolny framework** (`eval`) - prymityw subprocess: JSON na wejściu, werdykt
  i podpisany rekord na wyjściu, kody wyjścia 0/3/2.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "agent-safety-gate hook" } ] }
    ]
  }
}
```

Potem skalibruj na własnym zarejestrowanym ruchu, zanim cokolwiek zaczniesz
egzekwować:

```bash
agent-safety-gate calibrate .agent-safety-gate/records.jsonl --policy candidate.yaml
```

Snippety dla każdego hosta, mapowanie werdyktów na uprawnienia i reguły
wykrywania polityki są w [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Jak podejmuje decyzję

Dla każdego wywołania brama zbiera cztery sygnały plus jedną obserwację o samym
agencie. Każdy niesie informację, skąd pochodzi i czy to źródło jest niezależne
od bramkowanego agenta.

| Sygnał | Wartości | Skąd pochodzi |
| --- | --- | --- |
| `action_class` | `read_only` / `reversible_write` / `irreversible` / `external_effect` | z wpisu polityki dla tego narzędzia, nigdy z heurystyki |
| `scope_match` | w zakresie / poza zakresem | dosłowne dopasowanie prefiksu ścieżki albo domeny do allowlisty |
| `approval_present` | jest / brak / niewymagana | plik nazwany skrótem akcji, w katalogu kontrolowanym przez operatora |
| `policy_coverage` | pokryte / brak wpisu | czy polityka w ogóle zna to narzędzie |
| `agent_self_assessment` | brak / samopoświadczenie | zarezerwowany klucz `agent_safety_gate` w wywołaniu |

Dwie zasady, które nigdy nie ustępują:

1. **Sygnał wytworzony przez bramkowanego agenta nigdy nie liczy się na korzyść
   PASS.** Wywołanie niosące własne zapewnienie agenta jest zapisywane z
   `independent: false` i blokowane. Samoocena może decyzję wyłącznie zaostrzyć.
2. **Brakujący sygnał zasila niepewność.** Brama nigdy nie wymyśla wartości ani
   severity dla czegoś, czego nie zmierzyła. Niezadeklarowane narzędzie daje
   niepewność, a nie zgadniętą klasę akcji.

Sygnały zamieniają się w dwie ograniczone liczby - score i uncertainty - które
jądro AOS przekłada na PASS, WARN albo BLOCK. Które liczby i jakie progi, to
polityka; samo porównanie to jądro. Ta granica jest rozpisana pole po polu w
[BOUNDARY.md](BOUNDARY.md).

### Te progi to wartości demonstracyjne

Wagi w `examples/demo_policy.yaml` istnieją po to, żeby demo było czytelne. Nie
są kalibrowane i nie są rekomendacją. Te same domyślne progi bywają trafne dla
jednego zadania i błędne dla innego: próg dobry dla agenta kodującego w jednym
repozytorium jest zły dla agenta, który może wysyłać maile w Twoim imieniu.

Świadomie nie ma tu żadnych progów „produkcyjnych". Kalibruj na własnym ruchu -
odtwórz sesję, dla której znasz odpowiedzi:

```bash
python benchmarks/workflow_replay.py --trace your_session.jsonl --policy your_policy.yaml
```

## Liczby i jak je odtworzyć

Każda liczba poniżej pochodzi z komendy w tym repozytorium. Uruchom ją u siebie;
wszystkie mierzone były na jednym zwykłym laptopie i żadna nie wyjdzie
identycznie u Ciebie.

### Odtworzenie sesji roboczej

`python benchmarks/workflow_replay.py`

| | |
| --- | --- |
| ślad | 71 wywołań: 61 zwykłych, 10 ryzykownych |
| catch rate | 100% (10/10 ryzykownych nie przeszło; 7 zablokowanych, 3 z ostrzeżeniem) |
| false alarm rate | 0% (0/61 zwykłych wywołań nie przeszło) |
| decyzja | p50 78 us, p95 179 us |
| decyzja + podpisany rekord | p50 255 us, p95 418 us |

Catch rate na śladzie napisanym przez tych samych ludzi, którzy napisali bramę,
pokazuje, że polityka pokrywa przypadki, o których pomyśleliśmy - i nic ponadto.
[benchmarks/README.md](benchmarks/README.md) mówi, czego jeszcze te liczby nie
mówią i jak zastąpić je liczbami z Twojej własnej sesji.

### Użyteczność na prawdziwej sesji

```bash
python benchmarks/session_replay.py ~/.claude/projects/<projekt>/<id-sesji>.jsonl
```

Uruchom to na własnej sesji. Poniższe liczby pochodzą z 269 wywołań narzędzi z
sesji agenta kodującego, która zbudowała to repozytorium, odtworzonych wobec
starannej pierwszej wersji polityki dla tego zestawu narzędzi. Nic w nim nie było
oznaczone jako łagodne czy ryzykowne, a polityki nie poprawiano po zobaczeniu
wyniku.

Samego śladu nie dołączamy: to dane sesji i nie nasza sprawa, żeby je
publikować. Traktuj więc te cztery liczby jako rozpisany przykład, a nie
benchmark do powtórzenia - komenda wyżej daje wersję, która się liczy, czyli
zmierzoną na Twoim własnym ruchu.

| | |
| --- | --- |
| po cichu (PASS) | 118 (43,9%) |
| oflagowane (WARN) | 18 (6,7%) |
| przerwane (BLOCK) | 133 (49,4%) |
| ile osobnych zgód by to wymagało | 133 |

**Połowa prawdziwej sesji by się zatrzymała, i całość to jedno narzędzie.**
Każde przerwanie to wywołanie `Bash`. Brama przypisuje klasę akcji per
narzędzie; shell może zrobić wszystko, więc jedyną uczciwą klasą jest dla niego
najgorsza rzecz, jaką potrafi - a brama nie przeczyta treści komendy, żeby
uznać inaczej. Narzędzie „do wszystkiego" jest więc albo zatwierdzane za każdym
razem, albo blokowane za każdym razem.

Czyli: przed agentem, którego narzędzia są wąskie i nazwane - serwer MCP z
`run_tests`, `git_commit`, `deploy` - klasy pasują, a przerwania trafiają tam,
gdzie operator chciał być pytany. Przed gołym shellem to approval fatigue z
dodatkowymi krokami. To realne ograniczenie MVP, znalezione pomiarem, nie
argumentacją; [benchmarks/README.md](benchmarks/README.md) rozpisuje je do
końca.

18 ostrzeżeń okazało się błędem polityki, nie ryzykiem: allowlista wymieniała
katalogi i zapomniała o plikach w korzeniu repozytorium, więc edycja `README.md`
liczyła się jako poza zakresem. Jedno uruchomienie na prawdziwej pracy to
wychwyciło. I to jest codzienne zastosowanie tego narzędzia: wyceluj je w pracę,
którą już wykonałeś, i zobacz, co powiedziałaby o niej Twoja polityka.

### Kalibracja na danych, których nikt z nas nie wyprodukował

`python benchmarks/independent_replay.py`

Wszystkie liczby wyżej pochodzą z ruchu wytworzonego na jednej maszynie przez
ludzi, którzy napisali bramę. Ta nie: odtwarza opublikowane ślady OpenHands ze
[zbioru na Hugging Face Hub](https://huggingface.co/datasets/nebius/SWE-rebench-openhands-trajectories) -
inny agent, inny model, 38 cudzych repozytoriów, 2 525 wywołań narzędzi.

| Co pokazała | Liczba |
| --- | --- |
| wywołań niezależnego agenta idących przez jeden shell „do wszystkiego" | 51,1% (własna sesja tego repo: 49,4%) |
| wywołań narzędzia edytora, które są w rzeczywistości odczytem (`command: view`) | 63,8% |
| wywołań zapisanych z inną klasą akcji, gdy polityka umie to wyrazić | 687 (27,2%) |

Dwie z tych liczb zmieniły narzędzie.

**Klasa na wartość argumentu.** Narzędzia edytora, które czyta i pisze, nie da
się opisać jedną klasą na narzędzie, więc polityka może teraz deklarować klasę
per wartość argumentu selektora. To nadal deklaracja - brama sprawdza wartość w
Twoim pliku i niczego nie wnioskuje. Zmierzone uczciwie: przesuwa 40,1% wywołań
do PASS wobec ostrożnej polityki jednoklasowej i **nic** wobec pragmatycznej;
zawsze zmienia natomiast to, co rekord mówi o tym, co wywołanie zrobiło.

**Przełącznik trybu.** Połowa realnej sesji idąca przez shell oznacza, że
egzekwująca brama zatrzymuje połowę pracy pierwszego dnia. `mode: observe`
zapisuje każdą decyzję i mimo to przepuszcza wywołanie, więc widzisz, co brama by
zrobiła, zanim zacznie odmawiać. Ten sam werdykt, to samo uzasadnienie, ta sama
remediacja; rekord niesie `policy_mode`, a `verify` wypisuje linię dla każdego
wywołania zdecydowanego i nieegzekwowanego. To krok wdrożeniowy, nie miejsce na
stałe.

**I jedna rzecz, którą serwery już mówią.** MCP pozwala serwerowi publikować
`readOnlyHint`, `destructiveHint` i `openWorldHint` o własnych narzędziach. Z 15
narzędzi na trzech publicznych serwerach referencyjnych robi to 14. `wrap --check`
wstawia je teraz jako *propozycje* do potwierdzenia, razem z argumentem zakresu
znalezionym w schemacie. MCP mówi wprost, że adnotacje to hinty, które klient ma
traktować jako niezaufane, więc nigdy nie docierają do decyzji bramy - trafiają
wyłącznie do szkicu Twojej polityki.

### Ile kosztuje proxy na wywołanie

`python benchmarks/proxy_overhead.py`

| Konfiguracja | p50 na `tools/call` |
| --- | --- |
| prosto do serwera narzędzi | 3,10 ms |
| przez proxy, które tylko przekazuje | 4,26 ms |
| przez `agent-safety-gate wrap` | 5,35 ms |

Samo proxowanie kosztuje 1,16 ms; brama dokłada 1,09 ms. Środkowy wiersz jest po
to, żeby ostatnia liczba była uczciwa: drugi proces i drugi round trip należą do
proxowania, a nie do decyzji.

### Podpięcie bramy do serwera, którego wcześniej nie używaliśmy

`python tools/measure_wiring.py --policy examples/public_server_policy.yaml --tool get_current_time --arguments '{"timezone": "Europe/Warsaw"}'`

Cel: [`mcp-server-time`](https://pypi.org/project/mcp-server-time/) z
referencyjnego zbioru serwerów MCP - pakiet spoza tego repozytorium, opakowany
bez zmiany choćby jednej jego linii.

| Krok | Czas (trzy uruchomienia) |
| --- | --- |
| `pip install mcp-server-time` | 2,5 s |
| rozpoznanie: uruchomienie go przez bramę i wypisanie narzędzi | 1,2-1,6 s |
| pierwsze prawdziwe wywołanie przez proxy, zakończone podpisanym rekordem | 1,5-2,1 s |

Części ludzkiej nie ma w tej tabeli, bo to jedna decyzja na narzędzie -
*czy `get_current_time` jest tylko do odczytu?* - a udawanie, że mierzy się
stoperem czyjś osąd, byłoby złym rodzajem benchmarku. Całą integracją jest
[`examples/public_server_policy.yaml`](examples/public_server_policy.yaml):
37 linii, z czego 8 deklaruje dwa narzędzia, a reszta to komentarze i progi.

## Obowiązki rejestrowania

Artykuł 12 EU AI Act wymaga, by systemy AI wysokiego ryzyka umożliwiały
automatyczne rejestrowanie zdarzeń w cyklu życia, tak aby późniejsza inspekcja
była możliwa.

Te rekordy są **zaprojektowane, by wspierać** ten rodzaj obowiązku: każdy niesie
to, co zdecydowano, na jakim wejściu, pod którą wersją polityki, ze skrótem,
który każdy może przeliczyć, i łańcuchem, który pokazuje, czy plik zmieniono
później. To artefakt dowodowy i dokładnie takiego artefaktu taki wymóg oczekuje.

To nie jest ocena zgodności, nie czyni systemu zgodnym i nikt tutaj nie jest
Twoim doradcą prawnym. Czy Twój system jest w zakresie i jakie masz obowiązki, to
pytanie do ludzi, którzy robią to zawodowo.

## Alternatywy i ile to jest warte

[docs/COMPARISON.md](docs/COMPARISON.md) umieszcza bramę wśród guardraili,
gatewayów MCP, platform obserwowalności, uprawnień hosta i sandboxów - łącznie z
tym, co każde z nich robi, a czego ta brama nie robi, i kiedy nie używać jej
wcale. W skrócie: tamte odpowiadają na „czy ta treść jest bezpieczna" albo „co
to może fizycznie dotknąć"; ta odpowiada na „czy zadeklarowana polityka na to
pozwoliła - dowodliwie, offline".

[docs/VALUE.md](docs/VALUE.md) to wycena, którą sami chcielibyśmy przeczytać
przed adopcją cudzego narzędzia bezpieczeństwa: który z trzech bólów jest
naprawdę usunięty, które twierdzenia pozostają nieudowodnione (żaden zewnętrzny
audyt nie przyjął jeszcze tych rekordów) i co sfalsyfikowałoby założenie.
Model ROI celowo nie ma żadnych liczb domyślnych:

```bash
python tools/roi_model.py --example
```

## Budżet zależności

Najpierw biblioteka standardowa. Jedno zdanie uzasadnienia na zależność, a
dodanie nowej oznacza usunięcie czegoś innego.

| Zależność | Po co |
| --- | --- |
| `cryptography` | Podpisywanie i weryfikacja rekordów algorytmem Ed25519. |
| `PyYAML` | Parsowanie jedynego pliku polityki, który edytuje operator. |
| `mcp` (extra `[mcp]`) | Proxy MCP i tylko ono: brama, rekordy i weryfikator działają bez niego. |

To cała lista, a `tests/test_project_constraints.py` przewraca się, jeśli
urośnie. Zero usług, zero bazy danych, zero demona: proxy to proces, rekordy to
pliki. Weryfikator pozostaje jednym plikiem HTML.

Rdzeń decyzyjny jądra AOS jest vendorowany zamiast być zależnością - powody są w
[BOUNDARY.md](BOUNDARY.md).

## Co tu jest

```text
src/agent_safety_gate/
  gate.py        sygnały na wejściu, PASS/WARN/BLOCK i podpisany rekord na wyjściu
  signals.py     co zmierzono, skąd i jak niezależnie
  policy.py      jedyny plik, który edytuje operator
  records.py     kanoniczne bajty, łańcuch skrótów, weryfikacja offline
  signing.py     Ed25519
  mcp_proxy.py   integracja MCP, jedyne miejsce importujące SDK MCP
  cli.py         demo, wrap, hook, eval, explain, verify, calibrate
  integrations.py  drzwi hook/eval/calibrate: bez żadnego frameworka
verifier/verify.html   jeden plik, bez sieci, upuść na niego plik rekordów
examples/              polityka demo, serwer narzędzi demo, opakowany serwer zewnętrzny
benchmarks/            odtworzenie sesji i narzut proxy, z własnym README
tools/verify_all.sh    wszystko poniżej, jedną komendą
```

```bash
bash tools/verify_all.sh
```

Uruchamia lint, typy, cały zestaw testów, kontrolę skrótu vendorowanego jądra,
weryfikator w headless Chromium, benchmark, audyt twierdzeń i szybki start -
dosłownie.

## Jądro pod spodem

Arytmetyka werdyktu pochodzi z
[RafineriaAI/aos-kernel](https://github.com/RafineriaAI/aos-kernel) v0.1.1,
publicznego demonstratora deterministycznych decyzji PASS/WARN/BLOCK z
odtwarzalnym materiałem dowodowym. Nie jest tutaj modyfikowane; zobacz
[NOTICE](NOTICE). Rekordy zapisane przez tę bramę są nadal akceptowane przez
`aos trust verify` samego jądra, co `tests/test_kernel_interop.py` sprawdza
wobec prawdziwego jądra, a nie wobec vendorowanej kopii.

## Licencja

Jeszcze nie wybrana. [LICENSE](LICENSE) to placeholder, a
[docs/OWNER_DECISIONS.md](docs/OWNER_DECISIONS.md) rozpisuje opcje i ich koszty.
Do tego czasu: wszystkie prawa zastrzeżone, ewaluacja mile widziana.

## Czego nie ma w tej wersji

Jedna klasa akcji na narzędzie, co pasuje do narzędzi nazwanych, a nie do
shella ogólnego przeznaczenia - zobacz
[Użyteczność na prawdziwej sesji](#użyteczność-na-prawdziwej-sesji).
MCP jest jedyną integracją; LangChain to kolejna faza. Zgody nie wygasają.
Proxowana jest tylko capability `tools`, więc prompty, zasoby i sampling nie są
przekazywane. Zarządzanie kluczami produkcyjnymi jest poza zakresem. Rzeczy
niezrobione żyją w issues, nie w komentarzach `TODO` - w kodzie ich nie ma, a
test tego pilnuje.
