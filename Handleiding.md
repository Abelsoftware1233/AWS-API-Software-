# ABEL123 :: CLOUD SENTINEL

AWS misconfig scanner + externe API/endpoint scanner.

## Starten

```bash
pip install -r requirements.txt
python app.py
```

Backend draait op `http://localhost:5000`. Open `index.html` in de browser
(of serveer via een simpele static server) — hij praat met de backend op
`API_BASE` in `script.js`.

## AWS credentials

Gebruik bij voorkeur een **read-only IAM user**. Minimaal benodigde
managed policy: `ReadOnlyAccess`, of een custom policy met:

- `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetPublicAccessBlock`,
  `s3:GetBucketEncryption`, `s3:GetBucketVersioning`
- `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`,
  `iam:ListAttachedUserPolicies`, `iam:GetAccountSummary`
- `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`
- `rds:DescribeDBInstances`
- `cloudtrail:DescribeTrails`
- `sts:GetCallerIdentity`

Credentials worden **niet gelogd of opgeslagen** — ze worden alleen
per request in-memory gebruikt om een boto3-sessie op te zetten.

Alle AWS-calls in `app.py` zijn read-only (`Describe*`, `List*`, `Get*`).
Er zit geen enkele destructieve/mutating call in de code.

## Endpoint scanner

Non-intrusieve checks: security headers, CORS, TLS-certificaat geldigheid,
HTTP-methodes via OPTIONS. Blokkeert scans naar private/lokale IP-ranges
(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc).

Scan alleen endpoints waarvoor je toestemming hebt.

## ⚠ Status: wat wel en niet getest is

Deze code is **niet end-to-end getest** tegen een echt AWS-account of een
live Flask-server. De sandbox waarin dit gebouwd is heeft geen
netwerktoegang, dus er kon geen `pip install` en geen echte serverrun
gedaan worden. Wat wel is gecontroleerd:

- `python3 -m py_compile app.py` → geen syntaxfouten
- AST-parse van alle functies → structuur klopt
- Handmatige code-review van elke route en elk check-blok

Wat **niet** geverifieerd is en dus mis kan gaan bij de eerste run:

### Mogelijke CORS-problemen
Als je `index.html` direct opent via dubbelklik (`file://`), kan de browser
`fetch()`-calls naar `http://localhost:5000` blokkeren. Symptoom: melding
"kon backend niet bereiken" terwijl de Flask-server wél draait.
Fix: serveer de frontend ook via HTTP:
```bash
python -m http.server 8000
```
en open `http://localhost:8000/index.html`.

### Dependency-versies
`requirements.txt` pint exacte versies (Flask 3.0.3, boto3 1.34.144, etc.)
die niet getest zijn op compatibiliteit met elkaar of met jouw Python-versie.
Als `pip install` faalt op een specifieke versie, probeer:
```bash
pip install flask flask-cors boto3 requests --break-system-packages
```
zonder versiepinning.

### boto3 exception handling
De `except (ClientError, BotoCoreError)` blokken zijn gebaseerd op
boto3-documentatie, niet op geteste live errors. Het is mogelijk dat een
specifieke AWS-fout (bv. bij een regio zonder toegang, of een service die
niet enabled is in je account) een andere exception gooit dan verwacht en
alsnog een onafgehandelde 500-error veroorzaakt. Als dat gebeurt: kopieer
de volledige stacktrace uit de Flask-terminal en stuur die door, dan fix
ik het gericht.

### IAM-permissies
De policy-lijst in dit document is gebaseerd op boto3/AWS API-documentatie,
niet op een geteste run tegen een echte `ReadOnlyAccess`-policy. Het is
mogelijk dat een enkele call (bv. `iam:GetAccountSummary`) een net iets
andere permissie-naam nodig heeft dan hier vermeld. Bij een
`AccessDenied`-fout in de resultaten: dat is verwacht gedrag (de check
faalt netjes met een "info"-finding), maar laat weten welke check het is
zodat ik de policy-lijst kan corrigeren.

### CSS/JS rendering
De frontend-styling (dark/cyan/violet thema) is niet visueel gecontroleerd
in een browser vanuit deze sandbox. Lay-out-issues op mobiel of in
specifieke browsers zijn niet uitgesloten.

### SSL-check en verouderde datetime-functie
`check_ssl_cert()` gebruikt `datetime.datetime.utcnow()`, wat deprecated is
sinds Python 3.12. Dit geeft een `DeprecationWarning`, geen crash, maar kan
in een toekomstige Python-versie stoppen met werken.

**Kortom:** de code zou moeten werken zoals beschreven, maar de eerste
keer dat je 'm draait is de eerste keer dat hij echt getest wordt. Stuur
foutmeldingen (browser console + Flask-terminal output) door zodra je ze
tegenkomt, dan los ik ze gericht op.
