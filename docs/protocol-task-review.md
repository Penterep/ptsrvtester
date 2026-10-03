# Kontrola tasků RDP, MSRPC a UPnP

Kontrola lokálních commitů a pracovních změn, 1.–2. 10. 2026. Konkrétní společné chyby byly opraveny všude, kde má požadavek odpovídající význam. Funkce specifické pro RDP se nepřidávaly do protokolů, které takový test nemají.

## Umístění změn

- Všechny opravy RDP, MSRPC a UPnP jsou v současném pracovním adresáři na větvi `rdp-msrpc`.
- UPnP [PR #35](https://github.com/Penterep/ptsrvtester/pull/35) byl sloučen 30. 9. 2026 v 08:57:46 UTC, merge commit `cde7071`.
- Aktuální vzdálený `main` (`bb8c755`) byl znovu ověřen 2. 10. 2026. Na tento základ je rebased všech 13 task commitů RDP/MSRPC. Po vyjmutí lokálních testových změn je poslední task commit `5e5597c`; jeho zdrojový strom je shodný s původním `6d07ddc`.
- Lokální merge `2e9f5dc` byl na požadavek uživatele odstraněn z historie větve. Nové task commity tvoří lineární historii.
- Aktuální opravy tvoří navazující commit na stejné větvi. Sdílený parser obsahuje registraci UPnP i opravy nápovědy a výstupu.
- Nové a změněné testy zůstávají pouze lokálně. Ze všech 13 nepublikovaných task commitů byly vyjmuty; jejich testový strom odpovídá `origin/main`. Původní testy v repozitáři zůstaly zachované. Kontrolní součty ověřily přesné zachování všech 49 lokálních testovacích souborů.
- Původní task historie je zachována v lokální záložní větvi `backup/rdp-msrpc-before-local-tests-20261002`; obsah souborů je rovněž v `.worktrees/commit-backup-20261002`.
- Původní UPnP worktree `.worktrees/upnp`, záloha `.worktrees/integration-backup-20261001` a předrebase záloha `.worktrees/rebase-backup-20261002` zůstávají zachované. Nic nebylo pushnuto.

## Přehled požadavků

| Task | RDP | MSRPC | UPnP |
|---|---|---|---|
| Cíl přes `-tg/--target` | Ověřeno; povinný přepínač | Ověřeno; povinný přepínač | Ověřeno; povinný přepínač |
| Nedostupný cíl/port: rychlé ukončení | Jedna platná X.224 odpověď před testy, celkový časový limit; bez odpovědi konec před testy | Kontrola každého zvoleného transportu; nativní síťové selhání vyřadí další testy stejného transportu, ostatní pokračují | Bez platné SSDP odpovědi se přeskočí závislé testy; UDP mlčení není důkaz absence služby. Samostatný NOTIFY pokračuje. Selhání HTTP spojení nebo dotazu před odpovědí se neopakuje pro stejný endpoint/operaci |
| OS detection podle verze RDP | Samostatný `OSDETECT`; pouze orientační kandidáti, rodina RDP neurčuje jednoznačný OS | Specifické pro RDP | Specifické pro RDP |
| Verze RDP vypsaná dvakrát | Verze pouze v sekci `VERSION`; OS používá společnou uloženou sondu | Specifické pro RDP | Specifické pro RDP |
| Nezjištěný závěr: žluté `[*]` | Ověřeny capabilities, verze, OS, autentizace a TLS | Opraveny neúplné enumerace, odmítnutý přístup a nevyhodnotitelné credential testy | Opraveny neúplné discovery, description, SCPD, IGD, mapování, NOTIFY a EVENTS |
| Komunikační chyba: žluté `[*]` | Včetně selhání před první sekcí; skutečné nálezy zůstávají odlišené | Síťová selhání a přeskočené testy mají informační ikonu | Síťová selhání a nevyhodnotitelné záznamy mají informační ikonu |
| Malá nápověda `-ts TEST -h` | Každý test; ověřeno bez DNS/spojení | Doplněna pro všech 12 testů | Doplněna pro všech 7 testů |
| Seznam testů v hlavní nápovědě pod sebou s popisem | Ověřeno | Ověřeno | Sjednoceno; ALL popisuje výchozí trojici |
| RATELIMIT: spojit/ukončit a držet otevřené | Oba režimy, baseline/zátěž/recovery, celkový timeout. Samotné uzavření držených socketů neprokazuje omezování. Pozorovaná omezení nejsou důkaz konkrétní politiky | Takový test zde není | TCP test neodpovídá SSDP; nepřidával se |
| Přihlašovací parametry `-u/-U/-p/-P` | Ověřeny veřejné názvy a soubory; více přímých uživatelů pro BRUTE | Ověřeny veřejné názvy a soubory; více přímých uživatelů pro credential testy | Přihlašovací údaje se v těchto UPnP testech nepoužívají |
| Odstranit povinný `--allow-auth-failures` z BRUTEPROT | BRUTE tento přepínač nevyžaduje; USERENUM je samostatný test | Credential testy tento přepínač nemají | Takový test zde není |
| BRUTE: kombinace a platné přihlášení | Omezený součin zadaných zdrojů, ověřená autentizace, výpis úspěchu | Omezený součin zadaných zdrojů; odmítnutí Guest/SMB2 Null relace jako důkazu platných údajů; RPC potvrzení přístupu | Takový test zde není |
| BRUTE: chybějící ochrana před hádáním hesel | Vyhodnocení jen při dostatečných odmítnutých pokusech; síťová chyba nebo neúplný test nevytváří tento nález | Zdejší testy ověřují přihlašovací údaje; samostatné hodnocení ochrany RDP se nepřidávalo | Takový test zde není |
| BRUTE: procenta a aktuální kombinace | Živý účet/heslo, počet dokončených pokusů a skutečné procento dokončení před i po každém pokusu; zadané, generované i lockout série; JSON bez průběhu | Stejný sdílený průběh s procentem dokončených kombinací i při paralelní práci. Při výpadku se další pokusy neplánují a neotestovaná část je uvedena | Takový test zde není |
| BRUTEPROT přejmenovat na BRUTE | Ověřeny názvy, nápověda a příklady | Názvy BRUTEPIPE/BRUTESMB/BRUTETCP/BRUTEHTTP rozlišují odlišné transporty | Takový test zde není |
| Encryption level: Client Compatible a zastaralé úrovně jako Error | Ověřeno hodnocení všech známých legacy RDP úrovní; neznámá hodnota zůstává nevyhodnotitelná | RDP encryption level se zde nepoužívá | RDP encryption level se zde nepoužívá |
| Zarovnání EPM, UUID/Version/Name, TCP port a bindings | EPM formát zde není | EPM ověřeno: oddělené UUID/Version/Name, sloupce, host:port, TCP první a skupiny transportů; ENUMMGMT rovněž zarovnáno a UUID/Version odděleny | EPM formát zde není |
| Prázdné řádky mezi enumeračními záznamy | Samostatné sekce a existující výstup ověřeny | Doplněny mezi víceřádkovými MGMT/SAMR záznamy a ve výstupech do souboru | Doplněny mezi discovery, device, service, notification a event záznamy |
| Prázdné heslo `-p` i `-p ""` | Sjednoceno; vynechaný přepínač je `None`, explicitní prázdné heslo je `''` | Ověřeno až do autentizace a výsledků; prázdné heslo se nezahazuje ani nemění na text None | Přihlašovací údaje se zde nepoužívají |

## Další konkrétní opravy z kontroly

- RDP RATELIMIT nepřekračuje timeout při odpovědi posílané po bajtech.
- MSRPC nepovažuje SMB2 Null relaci za ověření zadaného účtu.
- MSRPC po první nativní síťové chybě nepokračuje všemi kombinacemi hesel.
- UPnP znovu nenavazuje spojení na odmítající HTTP port. Chyba před HTTP odpovědí blokuje pouze stejnou operaci; jiné porty, cesty a metody pokračují. HTTP/SOAP odpovědi, zamítnutí přístupu ani chyby parsování se necachují jako nedostupnost.
- JSON při fatální chybě neobsahuje ANSI sekvenci pro obnovení kurzoru; lidský výstup nadále kurzor obnovuje.

## Ověření

Po sjednocení oprav v hlavním pracovním adresáři prošlo 345 RDP, 326 MSRPC, 165 UPnP, 17 společných testů nápovědy/výstupu a 6 testů rendereru průběhu (859 celkem). Dále prošlo 8 přímých kontrol CLI: verze 1.4.8, globální nápověda, nápověda všech tří modulů a jednotlivých testů včetně prázdného hesla. `git diff --check` je bez chyb a `origin/main` je předkem současného HEAD. Testy zahrnují mockované odpovědi, skutečný offline NTLM bind a lokální TCP/UDP/HTTP servery. Vzdálené cíle ani skutečné účty nebyly testovány.

Po rebase 2. 10. 2026 byl ověřen shodný committed strom vůči předchozímu stavu a přesné zachování všech 45 rozpracovaných souborů. Při samotném rebase se změnil pouze popis historie v tomto dokumentu. Poté byl na další požadavek uživatele doplněn průběh popsaný níže.

Konkrétní lokální reprodukce:

- RDP sondy RATELIMIT s limitem 100 ms skončily při odpovědi po bajtech přibližně za 110 ms; před opravou jedna přijala odpověď až za 1,14 s.
- RDP nedostupný port skončil před testy s exit 1, žlutým `[*]` v textu a samostatně parsovatelným JSON bez nálezů.
- MSRPC mlčící RPC server: dvě spojení celkem (TCP kontrola a první RPC bind), další test stejné rodiny přeskočen; ostatní transporty se posuzují samostatně.
- UPnP odmítající control port: jedno spojení místo čtyř.
- UPnP mlčící control POST: jeden dotaz pro IGDINFO a PORTMAPS; jiná metoda i jiná cesta stále fungují.

MSRPC zachovává dosavadní procesní návratový kód 0 pro chyby jednotlivých modulů; JSON přitom uvádí `status: error`. Tento task neupravoval obecnou konvenci návratových kódů.

## Živý průběh BRUTE, 2. 10. 2026

Použitý vzor už existuje v SMTP, SSH a společném RATELIMIT: okamžitý výstup přes `ptlibs.ptprinthelper.ptprint` a přepisování terminálového řádku. RDP a MSRPC nově sdílejí `protocols/_shared/utils/progress.py`; nebylo potřeba měnit verzi ptlibs ani přidávat závislosti. Textový formát určuje náš renderer, ptlibs zajišťuje tisk a barvy. Nadbytečný druhý čítač Attempt a běžné stavy testing/completed byly na zpětnou vazbu uživatele odstraněny.

Textový výstup před autentizačním pokusem například:

```text
BRUTE Progress: 41/100 (41.0%) | User: 'alice' | Password: 'secret'
```

Čítač udává počet dokončených kombinací přihlašovacích údajů. Procento používá už dokončené pokusy, nikoli právě spuštěný pokus; v RDP celkový počet respektuje nastavený limit. Desetinné procento se nezaokrouhluje na 100 před dokončením. Předčasné zastavení zachovává skutečný dosažený podíl.

V terminálu se krátký řádek přepisuje a výslovně maže i na Windows; delší řádky se vypisují celé, aby se nepřekrývaly staré zalomené části a nezkracovalo heslo. Přesměrovaný výstup dostává běžné řádky. Účet i heslo jsou escapovány proti řídicím znakům. JSON neobsahuje průběhový text ani terminálové sekvence. Při dokončení či chybě se aktivní řádek ukončí před výsledky.

Ověřeny zadané kombinace, generované pokusy, lockout série, první blokující pokus, předčasný úspěch, síťová chyba, pořadí při paralelním dokončování a hranice 9999/10000. Kompletní sada 859 testů prošla po doplnění průběhu. Po následném zjednodušení formátu prošlo všech 694 dotčených testů RDP, MSRPC a společného výstupu.
