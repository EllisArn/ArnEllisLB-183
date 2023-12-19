# Applikationssicherheit verstehen und durch Implementation garantieren

## Einleitung

Dieses Portfolio dient dazu, mein Wissen aus dem Modul 183: Applikationssicherheit implementieren nachzuweisen. Ich werde auf aktuelle Sicherheitsbedrohungen eingehen, anhand von Beispielen wie Injection Sicherheitslücken erkennen und beheben. Weiterhin zeige ich die Verbesserung der Authentifizierung durch JWT-Token sowie die Bedeutung von Authentifizierung und Autorisierung für die Sicherheit von Anwendungen. Darüber hinaus erkläre ich defensives Programmieren und erläutere die Relevanz von Logging für die Sicherheit und dessen Implementierung. Für jedes Handlungsziel werde ich einen eigenen Abschnitt erstellen und anhand entsprechender Artefakte sowie deren Bewertung im Kontext des jeweiligen Ziels meine Erfüllung dieser Ziele darlegen.

| Handlungsziel | Beschreibung                                                                                                                                                                             |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1             | Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema (Erkennung und Gegenmassnahmen) beschaffen und mögliche Auswirkungen aufzeigen und erklären können. |
| 2             | Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können.                                                         |
| 3             | Mechanismen für die Authentifizierung und Autorisierung umsetzen können.                                                                                                                 |
| 4             | Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.                                                                                            |
| 5             | Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.                                                                                |

## Handlungsziel 1

### Artefakt

Hier eine Tabelle der OWASP Top 10 2021, welche ich mit den Informationen von der offiziellen Webseite erstellt habe:

| Sicherheitsrisiko                          | Tests                                              | Gegenmaßnahmen                                                         | Auswirkungen                                                                        |
| ------------------------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Broken Access Control                      | Authentifizierungsprüfungen, Zugriffskontrollen    | Verbesserte Zugriffskontrollen, Session-Verwaltung, Least-Privilege    | Unberechtigter Datenzugriff, Datenmanipulation, Identity Theft                      |
| Cryptographic Failures                     | Kryptographische Audits, Verschlüsselungsprüfungen | Implementierung aktueller Verschlüsselungsstandards, Schlüsselrotation | Offenlegung sensibler Daten, Systemkompromittierung, Brute-Force                    |
| Injection                                  | Penetrationstests, Code-Analyse                    | Eingabevalidierung, Prepared Statements, Parameterized Queries         | Datenverlust, Systemkompromittierung, SQL Injection                                 |
| Insecure Design                            | Risikoanalyse, Sicherheitsdesignprüfungen          | Threat Modeling, Sichere Designmuster, Input Validierung               | Designfehler, Schwierigkeiten bei der Fehlerbehebung, Broken Authentication         |
| Security Misconfiguration                  | Sicherheitskonfigurationsprüfungen                 | Automatisierte Konfigurationsprüfungen, Regelkonformität               | Sicherheitslücken, Unberechtigter Datenzugriff, Exposed Sensitive Data              |
| Vulnerable and Outdated Components         | Schwachstellenanalysen, Versionskontrolle          | Aktualisierung von Komponenten, Verwendung vertrauenswürdiger Quellen  | Bekannte Exploits, Anfälligkeit für Angriffe, Zero-Day Vulnerabilities              |
| Identification and Authentication Failures | Identitätsprüfungen, Authentifizierungstests       | Multifaktor-Authentifizierung, Sichere Authentifizierungsmethoden      | Identitätsdiebstahl, Zugriff durch nicht autorisierte Benutzer, Credential Stuffing |
| Software and Data Integrity Failures       | Integritätsprüfungen, Softwareupdatesprüfungen     | Verifizierung von Softwareupdates, Sichere CI/CD-Pipelines             | Kompromittierung von Datenintegrität, Schadsoftwareausführung, Tampered Software    |
| Security Logging and Monitoring Failures   | Überwachungstests, Logging-Analysen                | Implementierung von Logging, Überwachung kritischer Aktivitäten        | Unbemerkte Angriffe, Verzögerung der Reaktion auf Vorfälle, Evasion Techniques      |
| Server Side Request Forgery (SSRF)         | Tests für serverseitige Anfragen, Validierungen    | Inputvalidierung, Abschirmung von sensiblen Ressourcen                 | Umleitung von Anfragen, Ausnutzung von Serverressourcen, Information Disclosure     |

Quelle: [https://owasp.org/Top10/](https://owasp.org/Top10/)

### Wie wurde das Handlungsziel erreicht?

Das Ziel, aktuelle Bedrohungen zu erkennen und zu erläutern sowie Informationen zu Erkennung und Gegenmaßnahmen zu beschaffen, wurde durch die Zusammenstellung und Strukturierung der OWASP Top 10 2021 erreicht. Die Bereitstellung von Tests, Gegenmaßnahmen und potenziellen Auswirkungen bietet einen Überblick über die wichtigsten aktuellen Sicherheitsrisiken.

### Erklärung des Artefakts

Das Artefakt ist eine von mir serstellte Tabelle, die auf der offiziellen OWASP-Website basiert und die OWASP Top 10 für das Jahr 2021 präsentiert. Die OWASP Top 10 ist eine Rangliste der zehn häufigsten Sicherheitsrisiken im Bereich der Webanwendungen. Die Tabelle listet jedes Sicherheitsrisiko auf, beschreibt mögliche Tests zur Erkennung, Gegenmaßnahmen zur Minimierung des Risikos und potenzielle Auswirkungen, wenn das Risiko ausgenutzt wird.

Die Sicherheitsrisiken in der Tabelle reichen von "Broken Access Control" bis "Server Side Request Forgery (SSRF)". Für jedes Risiko werden Tests vorgeschlagen, um die Schwachstellen zu erkennen. Gegenmaßnahmen, wie verbesserte Zugriffskontrollen, Kryptographie-Audits oder sichere Authentifizierungsmethoden, werden empfohlen, um diese Risiken zu mindern. Die Auswirkungen reichen von unberechtigtem Datenzugriff über Identitätsdiebstahl bis hin zu Serverressourcenausnutzung.

### Kritische Beurteilung der Umsetzung des Artefakts

Ich denke, dass die Umsetzung des Artefakts gut gelungen ist. Die OWASP Top 10 ist eine sehr bekannte und anerkannte Liste von Sicherheitsrisiken, die regelmäßig aktualisiert wird. Die Liste ist sehr umfangreich und bietet einen guten Überblick über die wichtigsten Sicherheitsrisiken. Die Tabelle ist übersichtlich und strukturiert und bietet einen schnellen Überblick über die wichtigsten Informationen zu jedem Sicherheitsrisiko.

## Handlungsziel 2

### Artefakt

Hier ein Codeabschnitt, der anfällig für SQL Injection ist:

```csharp
[HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'",
                request.Username,
                MD5Helper.ComputeMD5Hash(request.Password));

            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```

Hier ein Codeabschnitt, der parametrisierte Abfragen verwendet, um SQL Injection zu verhindern:

```csharp
[HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string username = request.Username;
            string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = _context.Users
                .Where(u => u.Username == username)
                .Where(u => u.Password == passwordHash)
                .FirstOrDefault();


            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```

Quelle: InsecureApp aus den Aufträgen

### Wie wurde das Handlungsziel erreicht?

Das Ziel, Sicherheitslücken zu erkennen und zu beheben, wurde erreicht, indem der ursprüngliche Code, der anfällig für Manipulation durch SQL-Injection war, überarbeitet wurde. Die neue Implementierung entfernt direkte Einbettung von Benutzereingaben in die Datenbankabfrage und setzt auf eine strukturiertere Datenbankabfrage.

### Erklärung des Artefakts

Das Artefakt zeigt zwei Versionen eines Login-Codes. Die erste Version verwendete direkte Benutzereingaben in der SQL-Abfrage, was potenziell zu Sicherheitslücken durch SQL-Injection führte. Die aktualisierte Version verwendet eine strukturierte Methode, um Benutzereingaben sicherer zu verarbeiten und die Datenbankabfrage sicherer zu gestalten.

SQL-Injection ist eine Angriffstechnik, bei der ein Angreifer schädlichen SQL-Code in eine Anwendung einschleust. Dies geschieht oft durch Manipulation von Benutzereingaben, die direkt in SQL-Abfragen eingefügt werden.

Im ersten Codebeispiel konnte ein Angreifer potenziell die Login-Funktion ausnutzen, da die Eingaben des Benutzers direkt in die SQL-Abfrage eingefügt wurden. Diese Schwachstelle ermöglichte es dem Angreifer, zusätzlichen SQL-Code einzufügen und so die Anfrage zu verändern. Dadurch hätte er auf vertrauliche Daten zugreifen oder sogar die Datenbank manipulieren können. Wenn er als Benutzername `administrator ‘--` geschrieben und das Passwort nicht leer gelassen hätte, hätte er sich als Administrator anmelden können, ohne ein gültiges Passwort eingeben zu müssen.

Im aktualisierten Codebeispiel wurden potenzielle Sicherheitslücken behoben, indem direkte Einfügungen von Benutzereingaben in die SQL-Abfrage vermieden wurden. Stattdessen werden die Eingaben nun sicherer behandelt und als separate Variablen verwendet, um die Abfrage an die Datenbank zu stellen. Dadurch wird die Möglichkeit einer ungewollten Ausführung von eingeschleustem Code stark verringert.

Diese Verbesserung in deinem Code reduziert das Risiko von SQL-Injection, indem sie sicherstellt, dass Benutzereingaben nicht mehr als Teil der eigentlichen Abfragestruktur verwendet werden. Dies trägt dazu bei, deine Anwendung vor potenziellen Angriffen zu schützen, die auf das Ausnutzen von Schwachstellen in der Datenbankabfrage abzielen.

### Kritische Beurteilung der Umsetzung des Artefakts

Die Aktualisierung des Codes adressiert die grundlegenden Sicherheitslücken, die durch direkte Benutzereingaben in der SQL-Abfrage entstehen könnten. Es wurde auf eine sicherere Methode umgestellt, um potenzielle Angriffspunkte zu minimieren.

Jedoch könnte eine zusätzliche Sicherheitsebene hinzugefügt werden, indem eine verschlüsselte Speicherung von Passwörtern und die Verwendung von modernen, als sicher geltenden Hash-Algorithmen implementiert werden. Ebenso könnte die Implementierung einer Multi-Faktor-Authentifizierung oder zeitbasierten Sitzungsverwaltung die Gesamtsicherheit erhöhen.

## Handlungsziel 3

### Artefakt

#### Autorisierung

Ich habe JWT-Token verwendet, um die Autorisierung zu implementieren. Hier ein Codeabschnitt, der die Autorisierung überprüft und unterhalb der Methode, die das Token erstellt:

```csharp
[HttpPost]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(401)]
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }
    string username = request.Username;
    string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

    User? user = _context.Users
        .Where(u => u.Username == username)
        .Where(u => u.Password == passwordHash)
        .FirstOrDefault();

    if (user == null)
    {
        return Unauthorized("login failed");
    }

    if (user.SecretKey2FA != null)
    {
        string secretKey = user.SecretKey2FA;
        string userUniqueKey = user.Username + secretKey;
        TwoFactorAuthenticator authenticator = new TwoFactorAuthenticator();
        bool isAuthenticated = authenticator.ValidateTwoFactorPIN(userUniqueKey, request.UserKey);
        if (!isAuthenticated)
        {
            return Unauthorized("login failed");
        }
    }

    return Ok(CreateToken(user));
}

private string CreateToken(User user)
{
    string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
    string audience = _configuration.GetSection("Jwt:Audience").Value!;

    List<Claim> claims = new List<Claim> {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
    };

    string base64Key = _configuration.GetSection("Jwt:Key").Value!;
    SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

    SigningCredentials credentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.HmacSha512Signature);

    JwtSecurityToken token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        notBefore: DateTime.Now,
        expires: DateTime.Now.AddDays(1),
        signingCredentials: credentials
     );

    return new JwtSecurityTokenHandler().WriteToken(token);
}
```

Quelle: InsecureApp aus den Aufträgen

#### Authentifizierung

Hier ein Screenshot der 2FA-Authentifizierung mittels Google Authenticator:

![2FA-QR-Code](<Screenshot (20).png>) ![2FA-Anmenldung](<Screenshot (19).png>)

Ich konnte keinen Screenshot von innerhalb der Authenticator-App machen, da dies aufgrund von "Sicherheitsrichtlinien" nicht möglich ist.

### Wie wurde das Handlungsziel erreicht?

Das Ziel, Authentifizierungs- und Autorisierungsmechanismen zu implementieren, wurde erfolgreich umgesetzt. Es wurde JWT-Token für die Autorisierung verwendet und eine Zwei-Faktor-Authentifizierung (2FA) über den Google Authenticator integriert.

### Erklärung des Artefakts

Der obige Code demonstriert eine Login-Funktion, die die Anmeldeinformationen überprüft und dann ein JWT-Token generiert, das relevante Nutzerdaten enthält. Dieses Token ermöglicht autorisierten Zugriff auf die Systemressourcen. Die Zwei-Faktor-Authentifizierung über den Google Authenticator fügt eine zusätzliche Sicherheitsebene hinzu, um den Zugang weiter abzusichern.

### Kritische Beurteilung der Umsetzung des Artefakts

Die Implementierung von JWT-Token für die Autorisierung und die Integration von 2FA mittels Google Authenticator sind gute Mechanismen für die Authentifizierung und Autorisierung. Mir ist beim Implementieren aufgefallen, dass die Anwendung MD5-Hashing benutzt, was bedenklich ist. MD5 gilt als unsicherer Hash-Algorithmus, da er anfällig für Kollisionen und Brute-Force-Angriffe ist. Eine verbesserte Wahl wäre die Verwendung moderner, sichererer Hash-Algorithmen wie bcrypt, scrypt oder Argon2.

## Handlungsziel 4

### Artefakt

Passwortupdate-Funktion ohne Überprüfung des alten Passworts und Sicherheitsvalidierung des neuen Passworts:

```csharp
[HttpPatch("password-update")]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(404)]
public ActionResult PasswordUpdate(PasswordUpdateDto request)
{
    if (request == null)
    {
        return BadRequest();
    }

    var user = _context.Users.Find(request.UserId);
    if (user == null)
    {
        return NotFound(string.Format("User {0} not found", request.UserId));
    }
    user.IsAdmin = request.IsAdmin;
    user.Password = MD5Helper.ComputeMD5Hash(request.NewPassword);

    _context.Users.Update(user);
    _context.SaveChanges();

    return Ok();
}
```

Passwortupdate-Funktion mit Überprüfung des alten Passworts und Sicherheitsvalidierung des neuen Passworts:

```csharp
[HttpPatch("password-update")]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(404)]
public ActionResult PasswordUpdate(PasswordUpdateDto request)
{
    if (request == null)
    {
        return BadRequest("No request body");
    }

    var user = _context.Users.Find(request.UserId);
    if (user == null)
    {
        return NotFound(string.Format("User {0} not found", request.UserId));
    }

    if (user.Password != MD5Helper.ComputeMD5Hash(request.OldPassword))
    {
        return Unauthorized("Old password wrong");
    }

    string passwordValidation = validateNewPasswort(request.NewPassword);
    if (passwordValidation != "")
    {
        return BadRequest(passwordValidation);
    }

    user.IsAdmin = request.IsAdmin;
    user.Password = MD5Helper.ComputeMD5Hash(request.NewPassword);

    _context.Users.Update(user);
    _context.SaveChanges();

    return Ok("success");
}

private string validateNewPasswort(string newPassword)
{
    // Check small letter.
    string patternSmall = "[a-zäöü]";
    Regex regexSmall = new Regex(patternSmall);
    bool hasSmallLetter = regexSmall.Match(newPassword).Success;

    string patternCapital = "[A-ZÄÖÜ]";
    Regex regexCapital = new Regex(patternCapital);
    bool hasCapitalLetter = regexCapital.Match(newPassword).Success;

    string patternNumber = "[0-9]";
    Regex regexNumber = new Regex(patternNumber);
    bool hasNumber = regexNumber.Match(newPassword).Success;

    List<string> result = new List<string>();
    if (!hasSmallLetter)
    {
        result.Add("keinen Kleinbuchstaben");
    }
    if (!hasCapitalLetter)
    {
        result.Add("keinen Grossbuchstaben");
    }
    if (!hasNumber)
    {
        result.Add("keine Zahl");
    }

    if (result.Count > 0)
    {
        return "Das Passwort beinhaltet " + string.Join(", ", result);
    }
    return "";
}
```

Quelle: InsecureApp aus den Aufträgen

### Wie wurde das Handlungsziel erreicht?

Das Ziel, sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme zu berücksichtigen, wurde durch eine robustere Passwortupdate-Funktionalität erreicht. Die neue Implementierung prüft das alte Passwort vor der Aktualisierung und validiert das neue Passwort anhand von Kriterien wie Groß- und Kleinbuchstaben sowie Zahlen, um die Passwortsicherheit zu erhöhen.

### Erklärung des Artefakts

Die meisten Menschen verwenden dasselbe Passwort für mehrere Konten. Dies ist ein Sicherheitsrisiko, da ein Angreifer, der Zugriff auf ein Konto erhält, auch Zugriff auf andere Konten erhält, wenn er das Passwort errät. Die aktualisierte Funktion für das Passwortupdate überprüft nun das alte Passwort, bevor es geändert wird, und führt eine Validierung des neuen Passworts durch, um sicherzustellen, dass es bestimmte Sicherheitskriterien erfüllt (Großbuchstaben, Kleinbuchstaben, Zahlen). Dies stellt sicher, dass die neuen Passwörter bestimmten Sicherheitsstandards entsprechen.

### Kritische Beurteilung der Umsetzung des Artefakts

Die Überprüfung des alten Passworts vor der Änderung und die Validierung des neuen Passworts sind sinnvolle Verbesserungen, um die Sicherheit zu stärken. Allerdings könnte die Passwortrichtlinie weiter ausgebaut werden, z.B. durch die Anforderung einer Mindestlänge oder die Nutzung von Sonderzeichen. Wie bereits erwähnt, ist die Verwendung von MD5-Hashing bedenklich, da es als unsicher gilt. Eine weitere Verbesserung wäre die Verwendung moderner, sichererer Hash-Algorithmen wie bcrypt, scrypt oder Argon2.

## Handlungsziel 5

### Artefakt

LoginController ohne Logging:

```csharp
[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly NewsAppContext _context;

    public LoginController(NewsAppContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Login a user using password and username
    /// </summary>
    /// <response code="200">Login successfull</response>
    /// <response code="400">Bad request</response>
    /// <response code="401">Login failed</response>
    [HttpPost]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public ActionResult<User> Login(LoginDto request)
    {
        if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
        {
            return BadRequest();
        }

        string username = request.Username;
        string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

        User? user = _context.Users
            .Where(u => u.Username == username)
            .Where(u => u.Password == passwordHash)
            .FirstOrDefault();


        if (user == null)
        {
            return Unauthorized("login failed");
        }
        return Ok(user);
    }
}
```

LoginController mit Logging:

```csharp
[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly ILogger _logger;
    private readonly NewsAppContext _context;
    private readonly IConfiguration _configuration;

    public LoginController(ILogger<LoginController> logger, NewsAppContext context, IConfiguration configuration)
    {
        _logger = logger;
        _context = context;
        _configuration = configuration;
    }

    /// <summary>
    /// Login a user using password and username
    /// </summary>
    /// <response code="200">Login successfull</response>
    /// <response code="400">Bad request</response>
    /// <response code="401">Login failed</response>
    [HttpPost]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public ActionResult<User> Login(LoginDto request)
    {
        if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
        {
            return BadRequest();
        }
        string username = request.Username;
        string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

        User? user = _context.Users
            .Where(u => u.Username == username)
            .Where(u => u.Password == passwordHash)
            .FirstOrDefault();

        if (user == null)
        {
            _logger.LogWarning($"login failed for user '{request.Username}'");
            return Unauthorized("login failed");
        }

        _logger.LogInformation($"login successful for user '{request.Username}'");
        return Ok(CreateToken(user));
    }

    private string CreateToken(User user)
    {
        string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
        string audience = _configuration.GetSection("Jwt:Audience").Value!;

        List<Claim> claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
        };

        string base64Key = _configuration.GetSection("Jwt:Key").Value!;
        SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

        SigningCredentials credentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512Signature);

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.Now,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
         );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

Konfiguration des Loggers:

```csharp
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole(); // Console Output
    logging.AddDebug(); // Debugging Console Output
});
```

Audit-Trail mittels Datenbank-Triggern:

```csharp
    namespace M183.Migrations

{
/// <inheritdoc />
public partial class CreateTrigger : Migration
{
/// <inheritdoc />
protected override void Up(MigrationBuilder migrationBuilder)
{
migrationBuilder.CreateTable(
name: "NewsAudit",
columns: table => new
{
Id = table.Column<int>(type: "int", nullable: false)
.Annotation("SqlServer:Identity", "1, 1"),
NewsId = table.Column<int>(type: "int", nullable: false),
Action = table.Column<string>(type: "nvarchar(max)", nullable: false),
AuthorId = table.Column<int>(type: "int", nullable: false)
},
constraints: table =>
{
table.PrimaryKey("PK_NewsAudit", x => x.Id);
});

            migrationBuilder.Sql(@"CREATE TRIGGER news_insert ON dbo.News
                AFTER INSERT
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = ins.ID FROM INSERTED ins;
                SELECT @AuthorId = ins.AuthorId FROM INSERTED ins;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Create', @AuthorId);");

            migrationBuilder.Sql(@"CREATE TRIGGER news_update ON dbo.News
                AFTER UPDATE
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = ins.ID FROM INSERTED ins;
                SELECT @AuthorId = ins.AuthorId FROM INSERTED ins;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Update', @AuthorId);");


            migrationBuilder.Sql(@"CREATE TRIGGER news_delete ON dbo.News
                AFTER DELETE
                AS DECLARE
                  @NewsId INT,
                  @AuthorId INT;
                SELECT @NewsId = del.ID FROM DELETED del;
                SELECT @AuthorId = del.AuthorId FROM DELETED del;

                INSERT INTO NewsAudit (NewsId, Action, AuthorId) VALUES (@NewsId, 'Delete', @AuthorId);");

        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "NewsAudit");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_insert");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_update");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS news_delete");
        }
    }

}
```

Quelle: InsecureApp aus den Aufträgen

### Wie wurde das Handlungsziel erreicht?

Das Ziel, Informationen für Auditing und Logging zu generieren sowie Auswertungen und Alarme zu definieren und zu implementieren, wurde erreicht. Die Implementierung umfasst die Verwendung von ILogger für Logging und die Einrichtung von Datenbank-Trigger-basiertem Audit-Trail für die Überwachung von Änderungen in der News-Tabelle.

### Erklärung des Artefakts

Die Aktualisierung des LoginController (und anderen) umfasst die Integration von ILogger, um wichtige Ereignisse wie erfolgreiche oder fehlgeschlagene Anmeldeversuche zu protokollieren. Zudem wurde ein Audit-Trail mittels Datenbank-Triggern implementiert (news_insert, news_update, news_delete), um Änderungen in der News-Tabelle zu protokollieren und in der NewsAudit-Tabelle zu speichern.

### Kritische Beurteilung der Umsetzung des Artefakts

Logging: Die Verwendung von ILogger ist die vermutlich meistbenutzte Methode, um Informationen über das Systemverhalten zu erfassen. Es bietet Transparenz und kann bei der Fehlersuche und Überwachung helfen. Es wäre jedoch hilfreich, spezifischere Informationen im Log festzuhalten.

Audit Trail mit Triggern: Die Verwendung von SQL Server Triggern für das Auditing ist eine gute Methode, um Änderungen zu protokollieren. Allerdings sollte darauf geachtet werden, dass die Audit-Tabelle sicher ist und nur von autorisierten Benutzern modifiziert werden kann. Zudem könnte die Audit-Tabelle um zusätzliche Informationen wie Details der Änderungen erweitert werden.

## Selbsteinschätzung

Auch wenn ich vielleicht nicht alles zu 100% abdecken konnte, denke ich, dass ich den Grossteil der Kompetenzen im Modul 183 erreicht habe. Das, bei dem ich mir wahrscheinlich am unsichersten war, ist wie ich das Erreichen der Handlungsziele richtig beschreiben soll. Auch wenn das Modul 183 nicht mein Lieblingsmodul war, da ich so viel Theorie nicht besonders mag, habe ich doch einiges gelernt. Ich denke, dass ich das Wissen, das ich in diesem Modul erworben habe, in Zukunft gut gebrauchen kann.
