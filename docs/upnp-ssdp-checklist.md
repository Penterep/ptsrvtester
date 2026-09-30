# PTSRVTESTER: UPnP/SSDP: Checklist

Stav k 28. 9. 2026. Implementace je na lokální větvi `feature/upnp-ssdp`.

## Základ a bezpečné hranice

- [x] Samostatný protokol `upnp` v CLI a registry, moduly `DISCOVER`, `DESCRIBE`, `IGDINFO`, `SCPD`, `PORTMAPS`, `NOTIFY`, `EVENTS`.
- [x] Povinný cíl `-tg`, IPv4/IPv6 adresa nebo hostname; síťové operace jsou připnuté k jedné přeložené adrese. Hostname používá IPv4, nebo IPv6 s `--family 6`.
- [x] Výchozí průchod spouští `DISCOVER`, `DESCRIBE`, `IGDINFO`. `SCPD`, `PORTMAPS`, `NOTIFY` a `EVENTS` vyžadují explicitní výběr, také při `-ts ALL`.
- [x] Časové, početní a velikostní limity požadavků; průběžné výsledky a dosažené limity zůstávají v JSONu.

## SSDP a popisy zařízení

- [x] `DISCOVER`: cílený unicast M-SEARCH, zpracování odpovědí, základní validace hlaviček, deduplikace a záznam zdroje.
- [x] Volitelný multicast M-SEARCH na `239.255.255.250:1900` se zadaným místním IPv4 rozhraním, omezeným `MX` a `TTL`. Uchovávají se jen odpovědi od cíle `-tg`.
- [x] IPv6 unicast a multicast M-SEARCH na `FF02::C`/`FF05::C` s místním indexem rozhraní, filtrem cílové adresy a link-local scope.
- [x] `NOTIFY`: explicitní pasivní příjem oznámení `ssdp:alive`, `ssdp:byebye`, `ssdp:update` přes IPv4 i IPv6 s omezenou dobou, počtem paketů a filtrem IP adresy/scope cíle; bez dalších síťových požadavků.
- [x] `DESCRIBE`: načtení `LOCATION` přes HTTP(S) pouze ze zvoleného cíle, bez následování přesměrování; parsování zařízení, vnořených zařízení a inzerovaných služeb.
- [x] `SCPD`: explicitní načtení XML popisů služeb, akcí, argumentů a stavových proměnných. Limit 20 požadavků ve výchozím stavu, nejvýše 100, 256 KiB na odpověď a 8 MiB celkem.
- [x] `EVENTS`: explicitní dočasný GENA odběr s lokálním HTTP callbackem, filtrem IP cíle a SID, zpracováním XML/chunked událostí a ukončením `UNSUBSCRIBE`. Nejvýše pět služeb, 30 s poslechu na službu, 1000 událostí a 8 MiB těl na spuštění.
- [x] Odmítnutí DTD a entit, limity struktury XML a velikosti dat.

## IGD

- [x] `IGDINFO`: vybrané read-only akce `GetStatusInfo`, `GetNATRSIPStatus`, `GetExternalIPAddress` pro podporované služby WANIPConnection a WANPPPConnection.
- [x] `PORTMAPS`: pouze explicitně zvolený read-only výpis `GetGenericPortMappingEntry`, globální limit počtu záznamů a konec enumerace při UPnP chybě 713.
- [x] Řídicí URL zůstává na cíli; SOAP akce jsou na pevném seznamu. Odmítnutí přístupu, nepodporovaná akce a chyba transportu mají oddělené výsledky.
- [x] Nejvýše pět způsobilých IGD služeb a společný limit 32 MiB SOAP odpovědí na spuštění.

## Ověření a další fáze

- [x] Automatizované testy pro CLI, rámování SSDP a SOAP, scope cíle, XML, limity a částečné výsledky; lint upraveného kódu.
- [ ] Ověřit unicast, multicast, NOTIFY, SCPD, IGD akce a GENA callback na skutečném UPnP zařízení; zaznamenat odlišnosti implementací.
- [x] Přidat cílené IPv6 SSDP unicast/multicast včetně link-local scope a připnutí HTTP(S) spojení ke zvolené adrese a rozhraní.
- [x] Rozšířit pasivní `NOTIFY` a GENA `EVENTS` také na IPv6 s kontrolou místního rozhraní a link-local scope.
- [ ] Případné PTV nálezy definovat až s jednoznačným důkazem; samotná dostupnost UPnP nebo mapování portu zranitelnost nepotvrzuje.

Protokolové podklady: [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0-20140901.pdf), [WANIPConnection v1](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v1-Service.pdf), [WANIPConnection v2](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf), [WANPPPConnection v1](https://upnp.org/specs/gw/UPnP-gw-WANPPPConnection-v1-Service.pdf).
