# AutoValue Pro dauerhaft betreiben

Diese Anwendung ist für einen Node-/Docker-Host vorbereitet. Damit der PC nicht mehr laufen muss, wird sie auf einem Hosting mit dauerhaftem Speicher betrieben.

Der Hosting-Dienst muss lediglich diese Voraussetzungen erfüllen:

- Docker-Container aus diesem Projekt starten
- HTTPS und eine eigene Webadresse bereitstellen
- Einen persistenten Speicher an `/app/data` anbinden
- Den Port aus der Umgebungsvariable `PORT` nach außen erreichbar machen

Die Datei `data/autovalue-pro.json` enthält die gemeinsamen Fahrzeugdaten und Benutzerkonten. Sie muss auf einem dauerhaften Speicher liegen und regelmäßig gesichert werden. Beim ersten Aufruf richtet ihr die zwei Benutzerkonten selbst ein.

Wichtig: Die Anwendung sollte öffentlich ausschließlich über HTTPS bereitgestellt werden. Für die Live-Synchronisierung dürfen keine Server-Instanzen ohne gemeinsam genutzten persistenten Speicher parallel betrieben werden.
