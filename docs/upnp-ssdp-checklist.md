# PTSRVTESTER: UPnP/SSDP: Checklist

Stav k 28. 9. 2026. Implementace je na lokální větvi `feature/upnp-ssdp`.

## Základ a bezpečné hranice

- [x] Samostatný protokol `upnp` v CLI a registry, moduly `DISCOVER`, `DESCRIBE`, `IGDINFO`, `SCPD`, `PORTMAPS`, `NOTIFY`.
- [x] Povinný cíl `-tg`, IPv4 adresa nebo hostname; síťové operace jsou připnuté k jedné přeložené IPv4 adrese.
- [x] Výchozí průchod spouští `DISCOVER`, `DESCRIBE`, `IGDINFO`. `SCPD`, `PORTMAPS` a `NOTIFY` vyžadují explicitní výběr, také při `-ts ALL`.
- [x] Časové, početní a velikostní limity požadavků; průběžné výsledky a dosažené limity zůstávají v JSONu.

## SSDP a popisy zařízení

- [x] `DISCOVER`: cílený unicast M-SEARCH, zpracování odpovědí, základní validace hlaviček, deduplikace a záznam zdroje.
- [x] Volitelný multicast M-SEARCH na `239.255.255.250:1900` se zadaným místním IPv4 rozhraním, omezeným `MX` a `TTL`. Uchovávají se jen odpovědi od cíle `-tg`.
- [x] `NOTIFY`: explicitní pasivní příjem oznámení `ssdp:alive`, `ssdp:byebye`, `ssdp:update` na zadaném místním IPv4 rozhraní s omezenou dobou, počtem paketů a filtrem IP adresy cíle; bez dalších síťových požadavků.
- [x] `DESCRIBE`: načtení `LOCATION` přes HTTP(S) pouze ze zvoleného cíle, bez následování přesměrování; parsování zařízení, vnořených zařízení a inzerovaných služeb.
- [x] `SCPD`: explicitní načtení XML popisů služeb, akcí, argumentů a stavových proměnných. Limit 20 požadavků ve výchozím stavu, nejvýše 100, 256 KiB na odpověď a 8 MiB celkem.
- [x] Odmítnutí DTD a entit, limity struktury XML a velikosti dat.

## IGD

- [x] `IGDINFO`: vybrané read-only akce `GetStatusInfo`, `GetNATRSIPStatus`, `GetExternalIPAddress` pro podporované služby WANIPConnection a WANPPPConnection.
- [x] `PORTMAPS`: pouze explicitně zvolený read-only výpis `GetGenericPortMappingEntry`, globální limit počtu záznamů a konec enumerace při UPnP chybě 713.
- [x] Řídicí URL zůstává na cíli; SOAP akce jsou na pevném seznamu. Odmítnutí přístupu, nepodporovaná akce a chyba transportu mají oddělené výsledky.
- [x] Nejvýše pět způsobilých IGD služeb a společný limit 32 MiB SOAP odpovědí na spuštění.

## Ověření a další fáze

- [x] Automatizované testy pro CLI, rámování SSDP a SOAP, scope cíle, XML, limity a částečné výsledky; lint upraveného kódu.
- [ ] Ověřit unicast, multicast, NOTIFY, SCPD a IGD akce na skutečném UPnP zařízení; zaznamenat odlišnosti implementací.
- [ ] Samostatně implementovat GENA události s explicitním callback serverem, limity a vždy provedeným `UNSUBSCRIBE`, pokud budou součástí požadovaného rozsahu.
- [ ] Přidat cílené IPv6 SSDP včetně link-local scope a připnutí HTTP(S) spojení ke zvolené adrese a rozhraní, pokud bude součástí požadovaného rozsahu.
- [ ] Případné PTV nálezy definovat až s jednoznačným důkazem; samotná dostupnost UPnP nebo mapování portu zranitelnost nepotvrzuje.

Protokolové podklady: [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0-20140901.pdf), [WANIPConnection v1](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v1-Service.pdf), [WANIPConnection v2](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf), [WANPPPConnection v1](https://upnp.org/specs/gw/UPnP-gw-WANPPPConnection-v1-Service.pdf).
