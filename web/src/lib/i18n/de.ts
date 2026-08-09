import type { Messages } from './en';

/**
 * The annotation is the point: leave out a key, or misname one, and this file
 * stops compiling.
 */
export const de: Messages = {
	meta: {
		title: 'mailreportd — DMARC- und TLS-Berichte für den eigenen Mailserver',
		description:
			'Ein einzelnes Binary, das DMARC-Aggregat- und SMTP-TLS-Berichte aus einem Postfach einliest, jeden Absender gegen den eigenen SPF-Eintrag einordnet und beschränkte Prometheus-Metriken exportiert. Kein SaaS, keine Daten verlassen das eigene Netz.',
		ogAlt: 'mailreportd — Einlesen von DMARC- und SMTP-TLS-Berichten',
		localeName: 'Deutsch'
	},
	nav: {
		skipToContent: 'Zum Inhalt springen',
		capabilities: 'Funktionen',
		cardinality: 'Kardinalität',
		metrics: 'Metriken',
		start: 'Schnellstart',
		themeToggle: 'Farbschema wechseln',
		languageLabel: 'Sprache'
	},
	hero: {
		eyebrow: 'Observability für den eigenen Mailserver',
		title: 'Ihr Mailserver fällt lautlos aus.',
		titleAccent: 'Das hier sagt Ihnen Bescheid.',
		lede: 'mailreportd liest die DMARC- und SMTP-TLS-Berichte, die Empfänger Ihnen ohnehin schon schicken, und macht daraus Metriken, auf die sich alarmieren lässt. Ein Binary, eine Konfigurationsdatei, ein Postfach.',
		primaryCta: 'Zum Schnellstart',
		secondaryCta: 'Was exportiert wird',
		terminalCaption: 'Einlesen aus einem laufenden Postfach',
		badges: {
			selfHosted: 'Läuft auf eigener Hardware',
			noEgress: 'Kein Datenabfluss',
			singleBinary: 'Ein statisches Binary'
		}
	},
	problem: {
		heading: 'Stille ist nicht dasselbe wie Gesundheit',
		lede: 'Authentifizierung bricht auf Arten, die auf Ihrer Seite keinen einzigen Fehler erzeugen. Der Empfänger weiß Bescheid. Sie nicht — es sei denn, jemand liest, was der Empfänger zurückmeldet.',
		items: [
			{
				title: 'TLS wird still nicht mehr ausgehandelt',
				body: 'Ein Zertifikatswechsel, eine veraltete Policy, eine Firewall-Änderung. Absender fallen zurück oder scheitern, und Ihre Logs zeigen überhaupt nichts, weil der Fehler auf deren Seite der Verbindung passiert.'
			},
			{
				title: 'Signaturen scheitern beim Empfänger',
				body: 'Mail geht korrekt raus und kommt unauthentifiziert an. Ein rotierter Schlüssel, eine nicht ausgerichtete Signaturdomain, ein Relay, das Header umschreibt. Ihr MTA hat eine erfolgreiche Übergabe gemeldet.'
			},
			{
				title: 'Jemand anderes versendet in Ihrem Namen',
				body: 'Spoofing und vergessene Altsysteme tauchen ausschließlich in Aggregatberichten auf. Ohne sie auszuwerten ist der Schritt zu einer durchsetzenden Policy reine Vermutung.'
			}
		]
	},
	capabilities: {
		heading: 'Was gelesen wird',
		lede: 'Zwei per RFC definierte Berichtsformate, von jedem Empfänger, der sie verschickt — ohne dass Ihr MTA irgendetwas dazu beitragen muss.',
		items: [
			{
				tag: 'RFC 7489',
				title: 'DMARC-Aggregatberichte',
				body: 'Werden zu Authentifizierungsergebnissen pro Quelle verarbeitet, bewusst tolerant gegenüber den Abweichungen echter Absender vom veröffentlichten Schema — aufgefüllte Zahlen, ISO-Zeitstempel statt Unix-Sekunden, unerwartete Zeichensätze.'
			},
			{
				tag: 'RFC 8460',
				title: 'SMTP-TLS-Berichte',
				body: 'Sitzungszahlen und Fehlerdetails nach Ergebnistyp. Ein Absender, der keine TLS-Verbindung zu Ihnen aufbauen kann, wird damit zu einer Zahl im Dashboard statt zu Funkstille.'
			},
			{
				tag: 'RFC 7208',
				title: 'Absenderklassifikation über SPF',
				body: 'Jede meldende Quelle wird gegen den veröffentlichten SPF-Eintrag Ihrer Domain aufgelöst und als eigen, Weiterleitung oder unbekannt eingeordnet. Nichts an Ihrer Infrastruktur ist fest verdrahtet, es bleibt also korrekt, wenn sich Ihre Infrastruktur ändert.'
			},
			{
				tag: 'Zehn-Lookup-Grenze',
				title: 'Zustand des SPF-Eintrags',
				body: 'Dieselbe Auflösung zählt mit, wie viele DNS-Lookups Ihr Eintrag verbraucht. Über zehn ist es bei echten Empfängern ein permanenter Fehler — ein akuter Zustellbarkeitsdefekt, gemeldet als Metrik statt entdeckt im Störfall.'
			}
		]
	},
	cardinality: {
		heading: 'Quell-Adressen werden niemals zu Labels',
		lede: 'Ein Monat Aggregatberichte für eine Handvoll Domains enthält Zehntausende verschiedener Quell-Adressen, die meisten davon genau einmal gesehen. Diese als Prometheus-Labels zu exportieren würde genau die Datenbank zerlegen, die Sie damit füllen wollen.',
		explanation:
			'Deshalb hält der Speicher die vollständigen Details und Prometheus bekommt ausschließlich beschränkte Zeitreihen. Quellen werden vor dem Export in drei Kategorien eingeordnet; die Details pro Adresse liefert stattdessen eine JSON-API auf dem internen Listener.',
		assertion:
			'Diese Regel wird durch einen Test abgesichert, der die gesamte Ausgabe nach Quell-Adressen durchsucht.',
		pipeline: {
			caption: 'Vom Postfach zur Metrik',
			mailbox: 'Postfach',
			mailboxNote: 'IMAP, nur lesend',
			decode: 'Dekodieren',
			decodeNote: 'MIME, gzip, zip',
			parse: 'Parsen',
			parseNote: 'RFC 7489 / 8460',
			store: 'Speichern',
			storeNote: 'SQLite, volle Details',
			quarantine: 'Quarantäne',
			quarantineNote: 'bleibt erhalten',
			classify: 'Einordnen',
			classifyNote: 'gegen Ihr SPF',
			metrics: 'Metriken',
			metricsNote: 'beschränkte Reihen',
			api: 'JSON-API',
			apiNote: 'Details pro Quelle'
		},
		buckets: {
			heading: 'Drei Kategorien, aufgelöst über DNS',
			self: 'self',
			selfNote: 'Durch Ihren SPF-Eintrag autorisiert, oder durch eine ausdrückliche Ausnahme des Betreibers.',
			forwarder: 'forwarder',
			forwarderNote:
				'Nicht autorisiert, trägt aber eine ausgerichtete DKIM-Signatur — die Handschrift einer Weiterleitung, bei der SPF über den Zwischenschritt bricht und DKIM überlebt.',
			unknown: 'unknown',
			unknownNote: 'Alles andere. Genau diese Kategorie braucht Aufmerksamkeit.'
		}
	},
	metrics: {
		heading: 'Was exportiert wird',
		lede: 'Prometheus-Text auf einem internen Listener, daneben eine JSON-API für die Details, die keine Labels werden dürfen.',
		gaugeNote: {
			title: 'Mengen sind Gauges, keine Counter',
			body: 'Berichte treffen einen Tag verspätet und in beliebiger Reihenfolge ein, und die Aufbewahrung löscht alte wieder. Ein Counter wäre nicht monoton und rate() würde Unsinn liefern. Alarmieren Sie stattdessen auf Verhältnisse innerhalb des Zeitfensters.'
		},
		stalenessNote: {
			title: 'Veraltung ist ausdrückbar',
			body: 'Eine Fehlerrate von null, weil nichts eingelesen wurde, sieht genauso aus wie eine Fehlerrate von null, weil nichts fehlgeschlagen ist. Ein Zeitstempel des letzten Eingangs je Domain und Format macht beides unterscheidbar.'
		},
		tableCaption: 'Exportierte Metrikfamilien',
		columns: { metric: 'Metrik', labels: 'Labels' },
		alertsHeading: 'Wofür sich ein Alarm lohnt',
		alerts: [
			{
				severity: 'warning',
				title: 'Authentifizierung verschlechtert sich',
				body: 'Die Erfolgsquote Ihrer eigenen Quellen fällt über ein längeres Zeitfenster. Irgendwo scheitert Ihre Mail.'
			},
			{
				severity: 'warning',
				title: 'TLS-Aushandlung schlägt fehl',
				body: 'Jede fehlgeschlagene Sitzung über null. Es gibt keinen akzeptablen Grundwert dafür, dass Absender Sie nicht über TLS erreichen.'
			},
			{
				severity: 'never',
				title: 'Nicht auf die Berichtsmenge',
				body: 'Dass Aggregatberichte verspätet oder gar nicht eintreffen, ist völlig normal und nicht handlungsrelevant. Ein Alarm darauf bringt Leuten nur bei, Alarme zu ignorieren.'
			}
		]
	},
	guarantees: {
		heading: 'Betriebsgarantien',
		items: [
			{
				title: 'Ihr Postfach wird nie verändert',
				body: 'Der Feeder öffnet es nur lesend, liest per Peek statt Nachrichten als gelesen zu markieren, und merkt sich seine Position selbst. Das Postfach bleibt für Menschen oder andere Werkzeuge nutzbar.'
			},
			{
				title: 'Das Einlesen ist idempotent',
				body: 'Identische Bytes werden über die Prüfsumme erkannt, derselbe Bericht in einem anderen Umschlag über seine Berichtsidentität. Das gesamte Postfach neu zu verarbeiten ist gefahrlos und der vorgesehene Wiederherstellungsweg.'
			},
			{
				title: 'Nichts wird wegen eines Parse-Fehlers gelöscht',
				body: 'Nicht lesbare Berichte landen mit Fehlermeldung und Originalbytes in der Quarantäne und überstehen die Aufbewahrungsläufe. Abwesenheitsnotizen und Spam werden als ignoriert vermerkt, nicht als Fehler.'
			},
			{
				title: 'Protokolle, keine Produkte',
				body: 'Keine MTA-Admin-API, keine Provider-API, kein Log-Tailing, und keine Annahme darüber, welchen Mailserver, welches Dashboard oder welches Deployment-Werkzeug Sie einsetzen.'
			}
		]
	},
	start: {
		heading: 'Schnellstart',
		lede: 'Richten Sie es auf das Postfach, an das Ihre rua=-Adresse ohnehin zustellt. Das IMAP-Passwort wird über eine Umgebungsvariable benannt und nie in die Datei geschrieben — die Konfiguration bleibt damit einchekbar.',
		configCaption: 'config.yaml',
		runCaption: 'Starten',
		endpointsHeading: 'Zwei Listener',
		endpointsLede:
			'Sie transportieren Unterschiedliches. Die Lese-API legt Quell-Adressen und Absenderidentitäten offen — zusammen also Ihre gesamte Versandtopologie. Genau deshalb liegt sie nicht auf dem öffentlichen Listener.',
		publicLabel: 'Öffentlich',
		publicNote: 'darf nach außen',
		privateLabel: 'Intern',
		privateNote: 'bleibt innen'
	},
	footer: {
		tagline: 'Berichtsauswertung für alle, die ihre Mail selbst betreiben.',
		builtWith: 'In Go gebaut. Eingebettetes SQLite. Keine externen Dienste.',
		sections: {
			project: 'Projekt',
			standards: 'Standards'
		},
		links: {
			spec: 'Design-Spezifikation',
			readme: 'README',
			quickstart: 'Schnellstart'
		},
		rights: 'Alle Rechte vorbehalten.'
	}
};
