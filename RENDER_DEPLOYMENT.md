# AutoValue Pro bei Render bereitstellen

Für den dauerhaften Betrieb ohne laufenden PC ist Render vorbereitet. Die Datei `render.yaml` richtet einen Docker-Webdienst mit einem persistenten 1-GB-Datenspeicher ein. Darin liegen die zwei Benutzerkonten und der gemeinsame Fahrzeugbestand.

1. Ein Render-Konto erstellen oder anmelden.
2. Dieses Projekt in ein privates GitHub-Repository hochladen.
3. In Render **New → Blueprint** wählen und das Repository verbinden.
4. Die vorgeschlagene Konfiguration bestätigen.
5. Nach dem ersten Bereitstellen die Render-Webadresse öffnen und die zwei Benutzerkonten einrichten.

Render stellt HTTPS für die Webadresse bereit. Ein eigener Domainname kann später in den Diensteinstellungen ergänzt werden.

Der Dienst muss als einzelne Instanz mit dem persistenten Datenspeicher betrieben werden. Der Speicher darf nicht entfernt werden, da er die gemeinsamen Fahrzeugdaten enthält.
