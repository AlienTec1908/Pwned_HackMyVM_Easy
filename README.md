# Pwned - HackMyVM (Easy)

![Pwned.png](Pwned.png)

## Übersicht

*   **VM:** Pwned
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Pwned)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 10. Juli 2020
*   **Original-Writeup:** https://alientec1908.github.io/Pwned_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Pwned" zu erlangen. Der Weg dorthin begann mit der Entdeckung von FTP-Zugangsdaten (`ftpuser:B0ss_B!TcH`) im Quellcode einer Webseite (`/pwned.vuln`), die über eine benutzerdefinierte Wortliste (`secret.dic` aus `/hidden_text/`) gefunden wurde. Über FTP wurde ein privater SSH-Schlüssel für den Benutzer `ariana` heruntergeladen, der nicht passwortgeschützt war. Dies ermöglichte den SSH-Login als `ariana`. Die erste Rechteausweitung zum Benutzer `selena` gelang durch Ausnutzung einer Command Injection-Schwachstelle in einem Skript (`/home/messenger.sh`), das `ariana` mittels `sudo` als `selena` ausführen durfte. Die finale Eskalation zu Root erfolgte durch Ausnutzung der Mitgliedschaft des Benutzers `selena` in der `docker`-Gruppe, was das Starten eines privilegierten Docker-Containers mit gemountetem Host-Root-Verzeichnis ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `vi`
*   `ftp`
*   `cat`
*   `chmod`
*   `ssh2john` (impliziert für Key-Prüfung)
*   `ssh`
*   `sudo`
*   `docker`
*   Standard Linux-Befehle (`cut`, `grep`, `read` (in `messenger.sh`), `bash`, `id`, `python3`, `export`, `ls`, `chroot`, `sh`, `find`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Pwned" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.107) mit `arp-scan` identifiziert. (Port 21/FTP, 22/SSH, 80/HTTP offen laut späterer Analyse).
    *   `gobuster` auf Port 80 fand `/robots.txt`, `/nothing/` und `/hidden_text/`.
    *   In `/hidden_text/` wurde die Datei `secret.dic` (eine Wortliste) gefunden und heruntergeladen.
    *   `gobuster` mit `secret.dic` fand den Pfad `/pwned.vuln`.
    *   Im Quellcode von `/pwned.vuln` (oder einer dort verlinkten Datei) wurden auskommentierte FTP-Zugangsdaten gefunden: `ftpuser`:`B0ss_B!TcH`.

2.  **Initial Access (FTP & SSH als `ariana`):**
    *   Erfolgreicher FTP-Login als `ftpuser` mit dem Passwort `B0ss_B!TcH`.
    *   Im FTP-Verzeichnis `/share` wurden die Dateien `id_rsa` (privater SSH-Schlüssel) und `note.txt` gefunden und heruntergeladen.
    *   `note.txt` enthielt den Hinweis auf den Benutzernamen `ariana`.
    *   Mittels `ssh2john` wurde festgestellt, dass der `id_rsa`-Schlüssel nicht passwortgeschützt ist.
    *   Erfolgreicher SSH-Login als `ariana` mit dem privaten Schlüssel (`ssh ariana@pwnd.hmv -i id_rsa`).
    *   Die User-Flag 1 (`fb8d98be1265dd88bac522e1b2182140`) wurde in `/home/ariana/user1.txt` gefunden.

3.  **Privilege Escalation (von `ariana` zu `selena` via `sudo` & Command Injection):**
    *   `sudo -l` als `ariana` zeigte, dass das Skript `/home/messenger.sh` als Benutzerin `selena` ohne Passwort ausgeführt werden durfte: `(selena) NOPASSWD: /home/messenger.sh`.
    *   Das Skript `messenger.sh` las eine Nachricht (`msg`) ein und führte diese direkt als Befehl aus (`$msg 2> /dev/null`), was eine Command Injection ermöglichte.
    *   Durch Ausführen von `sudo -u selena /home/messenger.sh`, Eingabe eines beliebigen Benutzernamens und des Payloads `bash` als Nachricht, wurde eine Shell als `selena` erlangt.
    *   Die User-Flag 2 (`711fdfc6caad532815a440f7f295c176`) wurde in `/home/selena/user2.txt` gefunden.

4.  **Privilege Escalation (von `selena` zu `root` via Docker):**
    *   `id` als `selena` zeigte die Mitgliedschaft in der Gruppe `docker`.
    *   Mittels `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` wurde ein Docker-Container gestartet, der das Root-Verzeichnis des Host-Systems unter `/mnt` einband. Durch `chroot /mnt sh` wurde eine Shell mit Root-Zugriff auf das Host-System erlangt.
    *   Die Root-Flag (`4d4098d64e163d2726959455d046fd7c`) wurde in `/root/root.txt` (innerhalb des chroot, also `/mnt/root/root.txt`) gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure:**
    *   Benutzerdefinierte Wortliste (`secret.dic`) im Web-Root.
    *   Hardcodierte FTP-Credentials im Quellcode einer Webseite.
    *   Privater SSH-Schlüssel und Hinweis auf Benutzernamen auf FTP-Server.
*   **Command Injection:** Ein via `sudo` als anderer Benutzer ausführbares Skript (`messenger.sh`) nahm Benutzereingaben entgegen und führte sie unsicher als Shell-Befehle aus.
*   **Unsichere `sudo`-Regel:** Erlaubte die Ausführung eines verwundbaren Skripts als anderer Benutzer.
*   **Docker Group Privilege Escalation:** Die Mitgliedschaft eines Benutzers in der `docker`-Gruppe ermöglichte die Erlangung von Root-Rechten durch Starten eines privilegierten Containers.

## Flags

*   **User Flag 1 (`/home/ariana/user1.txt`):** `fb8d98be1265dd88bac522e1b2182140`
*   **User Flag 2 (`/home/selena/user2.txt`):** `711fdfc6caad532815a440f7f295c176`
*   **Root Flag (`/root/root.txt`):** `4d4098d64e163d2726959455d046fd7c`

## Tags

`HackMyVM`, `Pwned`, `Easy`, `Information Disclosure`, `FTP Exploit`, `Hardcoded Credentials`, `SSH Key Leak`, `sudo Exploit`, `Command Injection`, `Docker Privilege Escalation`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `vsftpd`
