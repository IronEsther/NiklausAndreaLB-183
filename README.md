# NiklausAndreaLB-183

## Einleitung
Dies ist die Leistungsbeurteilung von Andrea Niklaus. Im Modul 183 geht um Applikationssicherheit implementieren. In diesem Portfolio werde ich die Handlungsziele in je einem Abschnitt nachweisen, welche auch mindestens je ein Artefakt beinhalten werden.

## _Handlungsziel 1_

| Sicherheitsrisiko |	Beschreibung |	Gegenmassnahmen |	Auswirkungen |
| --- | --- | --- | --- |
| Broken Access Control |	Unbefugte Benutzer können ausserhalb ihrer eigentlichen Berechtigungen handeln |	Session-Verwaltung, Verbesserte Zugriffskontrollen | Unberechtigter Datenzugriff |
| Cryptographic Failures | Sicherheitsmassnahmen, funktionieren nicht richtig, welche eigentlich Daten schützen sollten. | Die sicheren Verschlüsselungsstandards benutzen und sensitive Informationen nicht unnötig speichern und darstellen | Sensible/Wichtige Daten werden gestohlen. |
| Injection (wie zum Beispiel SQL) | Unerlaubter Zugriff auf Daten oder Befehlen in einer Anwendung. | Sichere API nutzen, Eingabevalidierung | Unerlaubte Code-ausführung und Zugriff |

Quelle: [OWASP](https://owasp.org/Top10/)

### Wie habe ich dieses Handlungsziel erreicht:

Dieses Handlungsziel habe ich mit der Tabelle von der Website OWASP erreicht, welche im Auftrag verlinkt war. Damit habe ich dargelegt, dass ich die aktuellen Bedrohungen kenne und beschreiben kann. Im Auftrag selbst habe ich pro Problem die Auswirkungen und deren Gegenmassnahmen beschrieben, welche ich auch hier reinkopiert habe. 

### Erklärung des Artefaktes:

Das Artefakt/Die Tabelle stellt die 3 höchsten Bedrohungen dar. Dazu sieht man bei der Beschreibung, was die Bedrohung genau ist und welche Konzequenzen diese haben. Auch werden die Gegenmassnahmen beschrieben, um eine solche Bedrohung zu vermeiden. Wie oben schon erwähnt, habe ich diese Website von dem Auftrag, welche die Top 10 Bedrohungen zeigt, jedoch habe ich nur drei davon genommen. 

### Kritische Bewertung:

Das Tabellenlayout ist gut aufgebaut, damit Leser/innen dies gut lesen können. Während dem Erstellen des Artefakts jedoch hatte ich Zweifel, ob drei genug wären, jedoch habe ich mich nicht umentschieden und dies so gelassen. Vielleicht sollte ich nächstes Mal alles reintun, damit die Leser/innen die Website nicht extra nachschlagen müssen, um alle Bedrohungen zu sehen. 


## **_Handlungsziel 2_**

Als Artefakt habe ich den Codeauschnitt und die Veränderung im Auftrag LA_183_05_SQLInjection genommen.

### Artefakt: Codeabschnitt in der Login-Methode für SQL Injection-Schutz:**

```csharp
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }

//Alter Code:
  string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
  request.Username, 
  MD5Helper.ComputeMD5Hash(request.Password));

    //Neuer Code:
    string username = request.Username;
    string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

    User? user = _context.Users
        .Where(u => u.Username == username)
        .Where(u => u.Password == passwordHash)
        .FirstOrDefault();

      //Bis hier neu hinzugefügt

User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault(); //Dieser alter Code wurde gelöscht

//mehr code
}
```
### Wie wurde das Handlungsziel erreicht

Das Handlungsziel wurde erreicht, indem ich den Code verändert habe, um die Sicherheitslücke zu schliessen. Dabei habe ich die Sicherheitslücke und die Ursache von dem in der Applikation erkennt und diese gehoben habe, was nachweist, dass ich dieses Handlungsziel erfolgreich gelöst und verstanden habe. 

### Erklärung des Artefaktes:

Das Artefakt zeigt die veraltete und die neue Version im Code. Im veralteten Code bestand die Gefahr von einer SQL-Injection beim Einloggen. Dies wurde im Neuen Code aufgehoben, damit sich kein unauthorisierter Benutzer mit SQL Befehle wie -- vor dem Passwort schreiben könnte, etc. und somit ohne das Passwort anzugeben/wissen, sich in die Applikation einloggen zu können. Somit sind die Eingaben des Benutzers nicht mehr direkt in der SQL-Tabelle, sondern als separate Variable gespeichert. 

### Kritische Bewertung:

Die Aufträge von diesem Handlungsziel waren verständlich zu lösen, was auch dazu führte, dass ich den Artefakt wie auch die Erklärung gut und schnell machen konnte. Ich hatte keine Schwierigkeiten dabei. Beim Erstellen des Artefaktes habe ich auch geschaut, dass der Code sauber und verständlich mit den verschiedenen Änderungen gestalten ist. Die Änderungen im Code sind jedoch nur minimal und könnten erweitert werden, damit die Applikation noch sicherer wäre.

### XSS: In NewsController.cs:

```csharp
//Vorher:
  newNews.Header = request.Header;
  newNews.Detail = request.Detail;

//Nacher:
  newNews.Header = HttpUtility.HtmlEncode(request.Header);
  newNews.Detail = HttpUtility.HtmlEncode(request.Detail);

//mehr code....

//Vorher:
  news.Header = request.Header;
  news.Detail = request.Detail;

//Nacher:
  news.Header = HttpUtility.HtmlEncode(request.Header);
  news.Detail = HttpUtility.HtmlEncode(request.Detail);

//viiiel mehr code :D
```
### Screenshots

Vor der Änderung vom Code:
![HZ2_1](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/7793005e-56f8-4118-af9e-b17e20968c7f)

Nach der Änderung vom Code:
![HZ2_2](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/0d8d9605-44fd-4757-95ed-3e5edeaaee40)

### Wie wurde das Handlungsziel erreicht

Das Handlungsziel wurde erreicht, indem der Code im NewsController.cs angepasst wurde, um XSS-Sicherheitslücken zu schließen. Durch die Verwendung von ```HttpUtility.HtmlEncode``` wurde sichergestellt, dass Benutzereingaben, insbesondere im Zusammenhang mit den Feldern Header und Detail, vor der Ausgabe auf der Webseite korrekt codiert wurden. Dadurch wird das Risiko von Cross-Site Scripting (XSS) minimiert. Cross-Site Scripting ist deshalb gefährlich, weil Benutzer über dies JavaScript-Befehle (über Eingabefelder) senden kann, um die Website zu schädigen.

### Erklärung des Artefaktes:

Das Artefakt zeigt den Vergleich zwischen dem vorherigen Code und dem aktualisierten Code im NewsController.cs. In der vorherigen Version wurden Benutzereingaben direkt in die Header- und Detail-Felder der News übernommen, ohne auf mögliche XSS-Angriffe zu reagieren. Die aktualisierte Version verwendet ```HttpUtility.HtmlEncode```, um sicherzustellen, dass alle potenziell gefährlichen Zeichen in den Benutzereingaben korrekt codiert werden. Dies schützt die Anwendung vor XSS-Angriffen, bei denen bösartiger Code (ganz schlimm :o) in die Webseite eingefügt wird.

### Kritische Bewertung:

Die Umsetzung des Handlungsziels ist effektiv und entspricht bewährten Sicherheitspraktiken. Die Verwendung von HttpUtility.```HtmlEncode``` ist eine gute Methode, um XSS-Angriffe zu verhindern. Die minimalen Änderungen im Code sind klar und verständlich. Um die Sicherheit weiter zu verbessern, könnten zusätzliche Validierungen und Sicherheitsmechanismen in Erwägung gezogen werden.

### Erklärung Auftrag Unsaubere_API:

Beim Auftrag Unsaubere_API mussten wir die API an sich ändern, da es zu viel Daten an dem Server (für den Benutzer sichtbar) geschickt hatte, als es eigentlich hätte sollen. Deshalb mussten wir den Code überarbeiten, damit eine externe Person nicht die Anmeldedaten, die Newsdaten, usw. durch die Netzwerkanalyse herausfinden kann. 

Folgende Informationen wurden an den Server geliefert:
-	Id (Für Update / Delete)
-	Header (Wird angezeigt)
-	Detail (Wird angezeigt)
-	postedDate (Wird angezeigt)
-	isAdminNews (Wird angezeigt)
-	authorId  (Für die Anzeige der Updates / Delete Buttons)
-	author
  --	id (Wird nicht benötigt)
  --	username (Wird angezeigt)
  --	password (hash) (Wird nicht benötigt)
  --	isAdmin (Wird nicht benötigt)

Es wird fast alles benötigt aber der Passworthash + weitere Daten des Authors (wenn die Tabelle erweitert wird) dürfen nicht an den Server ausgeliefert werden.

### Artefakt:

Als Artefakt habe ich den Codeauschnitt und Screenshots in Relation mit diesem Codeabschnitt genommen:

### Codeabschnitt im NewsController.cs:

```csharp
//In NewsController.cs
public class NewsController : ControllerBase

//mehr Code...

[HttpPatch("{id}")]
[ProducesResponseType(200)]
[ProducesResponseType(403)] //Hinzugefügt
[ProducesResponseType(404)]

public ActionResult Update(int id, NewsWriteDto request)
{
  return NotFound(string.Format("News {0} not found", id));
}
//
if (!_userService.IsAdmin() && _userService.GetUserId() != news.AuthorId)
{
  return Forbid();
}
//Neu Hinzugefügt

//noch mehr code...

[HttpDelete("{id}")]
[ProducesResponseType(200)]
[ProducesResponseType(403)] //Neu Hinzugefügt
[ProducesResponseType(404)]

public ActionResult Delete(int id)
{
  return NotFound(string.Format("News {0} not found", id));
}

//
if (!_userService.IsAdmin() && _userService.GetUserId() != news.AuthorId)
{
  return Forbid();
}
//Neu hinzugefügt

//In diesem Code wurde nichts gelöscht
```

#### Screenshots:

![HZ1_1](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/e254fa13-6a71-4088-a521-920748630f7a)
![HZ1_2](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/6d74f29f-f302-4dbf-a987-7a7d59d0d002)
![HZ1_3](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/699709b4-0d24-40ca-b479-d0dd81160b43)


### Wie habe ich dieses Handlungsziel erreicht:

Im ersten Handlungsziel haben wir die Infrastruktur eingerichtet, die InsecureApp heruntergeladen, gestartet und den Aufbau der App angeschaut. Dann haben wir einige wichtige Grundbegriffe zusammen angeschaut, welche für den Verlauf vom Modul wichtig waren, wie zum Beispiel ```Vertraulichkeit```, ```Integrität``` und ```Verfügbarkeit```.

Beim praktischen Teil, den Auftrag ```LA_183_10_Business_Logic```, mussten wir bei der App den Newseintrag-Security verbessern. Die Sicherheitslücke war derjenige, dass jeder, wer die ID des News Eintrags kennt, dieser bearbeiten oder löschen kann. Der Benutzer / die Zugriffsrechte werden im Backend nicht geprüft. Dies mussten wir so umprogrammieren, dass der normale Benutzer nur noch ihre eigenen News bearbeiten und löschen kann.
Somit habe ich dieses Handlungsziel erreicht, indem ich die Zugriffsrechte, wie im Auftrag ```LA_183_10_Business_Logic``` gefordert, verbessert habe habe.

### Erklärung des Artefakts:

Das Artefakt belegt die Codeänderungen, welche ich in NewsController.cs vorgenommen habe, um die Applikation besser zu schützen. Somit wird sichergestellt, dass ein normaler Benutzer nur seine eigenen News bearbeiten und löschen kann. Die Überprüfung der Benutzerrechte wurde durch Hinzufügen von Bedingungen vor dem Aktualisieren und Löschen von News hinzugefügt.

### Kritische Bewertung:

Die verschiedene Änderungen sind erfolgreich und erfüllen das Handlungsziel. Die Überprüfung der Benutzerrechte wurde korrekt eingeführt, um nicht befugte Bearbeitung und Löschung von News zu verhindern. Das Artefakt ist strukturiert und mit dem Screenshot ist es einfach, dies zu intepretieren und lesen. 

### Erklärung des Screenshots:

Der User konnte mit Adminrechte einen 'AdminNews' erstellen (und kann diese immer noch bearbeiten.) Nach der Änderung kommt der Error 401 (siehe unterer Screenshot), wenn man versucht, einen Newsbeitrag als Admin zu erstellen, wenn man mit dem User Konto angemeldet ist.

## **_Handlungsziel 3_**

Als Artefakt habe ich den Codeauschnitt und die Veränderung im Auftrag LA_183_11_Autorisierung und LA_183_12_Authentifizierung genommen. 

```csharp
//Wichtige Veränderungen im LoginController.cs:

      private string CreateToken(User user)
      {
            //Neu:
            string username = request.Username;
            string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);
            //Veraltet und gelöscht:
            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
                request.Username, 
                MD5Helper.ComputeMD5Hash(request.Password));

            //Neu:
            User? user = _context.Users
                .Where(u => u.Username == username)
                .Where(u => u.Password == passwordHash)
                .FirstOrDefault();

            //Veraltet und gelöscht:
            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            //geblieben:
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            //Veraltet und gelöscht:
            return Ok(user);

            //Neu hinzufügt:
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

//Teile von diesem Code ist aus den Lösungen kopiert worden, da ich den Auftrag nicht fertigstellen konnte und mir deshalb Hilfe von den Lösungen geholt habe. 
```
### Wie wurde das Handlungsziel erreicht

Das Handlungsziel wurde erreicht, indem der Code im LoginController.cs angepasst wurde, um Broken Access Control zu beheben. Die Änderungen umfassen den Ersatz von direkten SQL-Abfragen durch sicherere Abfragen über Entity Framework Core. Dies gewährleistet einen sicheren Zugriff auf Benutzerinformationen und reduziert das Risiko von SQL-Injection-Angriffen. Für die Autorisierung wurde ein JWT-Token umgesetzt und für die 2FA wurde Google Authenticator installiert und benutzt. 

### Erklärung des Artefaktes:

Das Artefakt zeigt den relevanten Codeausschnitt aus den Aufträgen LA_183_11_Autorisierung und LA_183_12_Authentifizierung. Die Veränderungen betreffen die Art und Weise, wie Benutzerinformationen abgerufen werden, um sicherzustellen, dass der Zugriff auf die Datenbank sicherer ist. Die Verwendung von Entity Framework Core ersetzt die zuvor verwendeten direkten SQL-Abfragen.

### Kritische Bewertung:

Die Umsetzung des Handlungsziels ist effektiv und verbessert die Sicherheit der Anwendung erheblich. Der Wechsel von direkten SQL-Abfragen zu Entity Framework Core trägt dazu bei, das Risiko von Broken Access Control und SQL-Injection-Angriffen zu minimieren. Man könnte jedoch ein besseres Hashing benutzten, um die Sicherheit der Applikation zu erhöhen.

## **_Handlungsziel 4_**

Als Artefakt habe ich den Codeauschnitt und die Veränderung im Auftrag LA_183_13_HumanFactor und LA_183_15_PasswortHashing genommen.

### HumanFactor: UserController.cs+PasswortUpdateDTO.cs:

```csharp

//viiiiiel code davor, jedoch nicht so relevant für das

//Neu hinzugefügt:
if (user.Password != MD5Helper.ComputeMD5Hash(request.OldPassword))
  {
    return Unauthorized("Old password wrong");
  }

string passwordValidation = validateNewPasswort(request.NewPassword);
  if (passwordValidation != "")
  {
    return BadRequest(passwordValidation);
  }
//gelöscht, weil es zu wenig ausmacht und nicht viel aussagt:
  return Ok();

//Neu hinzugefügt: (Viiiel aussagekräftiger :o)
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
      result.Add("keinen Kleinbuchstaben :(");
    }
    if (!hasCapitalLetter)
    {
      result.Add("keinen Grossbuchstaben :c");
    }
    if (!hasNumber)
    {
      result.Add("keine Zahl. Bitte füge eine Hinzuu");
    }

    if (result.Count > 0)
    {
      return "Das Passwort beinhaltet " + string.Join(", ", result);
    }

return "";
```

### Screenshots:

Bei einem ungültigen altes Passwort:
![HZ4_1](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/76626c1a-9852-4dc1-a6f4-8c02285d19b4)

Bei einem gültigen altes Passwort:
![HZ4_2](https://github.com/IronEsther/NiklausAndreaLB-183/assets/89132005/2cd6fce5-a1e3-4269-b67f-6413d097ce2c)


### Wie wurde das Handlungsziel erreicht

Ich habe das Handlungsziel erreicht, indem ich im Artefakt hinzugefügt habe, dass man das altes Passwort angeben muss, um es zu ändern. Dabei werden sicherheitsrelevante Faktoren berücksichtigt. 

### Erklärung des Artefaktes:

Der Code wurde im AccountController.cs entsprechend angepasst. Dies beinhaltet eine bessere Strukturierung des Codes, das Hinzufügen von Kommentaren und die Bereitstellung von sinnvollen HTTP-Antwortcodes. Es überprüft das Passwort, bevor es geändert wird und führt eine Validierung des Passwortes durch: Grossbuchstaben, Kleinbuchstaben und Zahlen. Somit ist das Passwort stark genug, damit es nicht herausgefunden werden kann. Mit dem neuen Code kann daher ein externer Nutzer nicht einfach so das Passwort ändern, wenn er/sie das altes Passwort nicht weiss. Somit ist die Applikation ein wenig sicherer als vorher! Success 👍!

### Kritische Bewertung:

Die implementierten Änderungen verbessern die Lesbarkeit des Codes, die Verständlichkeit und die Übersichtlichkeit. Die Applikation ist sicher, jedoch kann man immer noch weitere Sicherheitsaspekte hinzufügen, wie zum Beispiel eine Mindestanzahl von Buchstaben im Passwort, eine zwei-Faktoren-Authentifizierung, etc.

## **_Handlungsziel 5_**

### Artefakt

Für den Logging Auftrag, LA_183_17_Logging und LA_183_51_AuditTrail, habe ich Inspiration von dem Code im Auftrag geholt und mit den Musterlösungen verglichen und verbessert.

```csharp
//LoginController.cs

//Alle using directories 

public class LoginController : ControllerBase
{

//Hinzugefügt:
private readonly ILogger _logger;

//gelöscht, weil es zu unspezifisch war:
public LoginController(NewsAppContext context, IConfiguration configuration)

//neu hinzugefügt, viel spezifischer sogar!!:O :
public LoginController(ILogger<LoginController> logger, NewsAppContext context, IConfiguration configuration)
{
   _logger = logger;

//Mehr code :O

//Neu Hinzugefügt:

_logger.LogWarning($"login failed for user '{request.Username}'");
_logger.LogInformation($"login successful for user '{request.Username}'");
}

```
Wichtige Änderungen Im NewsController:

```csharp
//NewsController.cs
public class NewsController : ControllerBase
  {

//Neu Hinzugefügt, verstreut über dem Code:
private readonly ILogger _logger;
//gelöscht, Grund war, weil es zu unspezifisch war:
public NewsController(NewsAppContext context, IUserService userService)
//Hinzugefügt:
public NewsController(ILogger<NewsController> logger, NewsAppContext context, IUserService userService)
_logger.LogInformation($"news entry created by {_userService.GetUsername()}");
_logger.LogWarning($"user {_userService.GetUsername()} tried to edit foreign news (id: {id})");
_logger.LogInformation($"news entry {id} updated by {_userService.GetUsername()}");
_logger.LogWarning($"user {_userService.GetUsername()} tried to delete foreign news (id: {id})");
_logger.LogInformation($"news entry {id} deleted by {_userService.GetUsername()}");
```

Konfiguration:
```csharp
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole(); // Console Output
    logging.AddDebug(); // Debugging Console Output
});
```

Audit-Trail:
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

Änderungen im Programm.cs:

```csharp
//Neu Hinzugefügt :D

// Logging Configuration
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole(); // Console Output
    logging.AddDebug(); // Debugging Console Output
});

```
### Wie wurde das Handlungsziel erreicht

Das Handlungsziel wurde mit dem erreicht, dass im Artefakt das Logging die Einrichtung vom Audit-Trail implementiert wurde, wie es in den Aufträgen erfordert war.

### Erklärung des Artefaktes:

Logging wurde mit ILogging ersetzt, um wichtige Informationen über den Anwendungsstatus zu erhalten. Das Artefakt zeigt die Integration von verbessertem Logging in verschiedenen Teilen der Anwendung, einschließlich des LoginControllers, des NewsControllers und der Konfiguration im Programm.cs. Der Audit-Trail wurde mit Datenbank-Triggern implementiert, um Änderungen zu protokollieren und zu speichern.

### Kritische Bewertung:

Die Implementierung des verbesserten Loggings erfüllt das Handlungsziel effektiv, indem sie eine detaillierte Protokollierung in verschiedenen Teilen der Anwendung ermöglicht. Das Artefakt zeigt, wie effektiv es ist, ILogger anstatt Logger zu benutzen, damit man die Informationen, wie auch die Verwendung von SQL Triggers, sicher speichern kann. Jedoch könnte die Applikation noch sicherer werden, jedoch weiss ich momentan nicht wie. (Vielleicht in der Zukunft)

## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls

In diesem Modul habe ich mich grundsätzlich sehr sicher gefühlt und hatte auch viel Freude an den Aufträgen, da es ein spezielles Modul war, wessen Thema wir nie durchgenommen haben. Im grossen und ganzem habe ich viel mitgenommen. Auch der Unterrichtstyl war passend, da der Lehrer immer da war, wenn wir Hilfe brauchten oder eine Frage hatten. Er hat auch den Unterricht so gestaltet, dass wir die Themen in unserem Tempo bearbeiten konnten. 

Das einzige, was nicht so gut geloffen ist, war dieser Portfolio-Eintrag. Ich war mir mit den Anforderungen nicht sicher, welche und wie ich die Artefakte belegen sollte, wie viel ich dazu schreiben musste, etc. Ich habe mich jedoch während dem Schreiben so gut wie möglich versucht an den Handlungszielen und Vorgaben festzuhalten. Alle Artefakte sind dabei während dem Modul enstanden, von den Aufträge oder von mir, ausser alle Sachen, die ich als 'externe Quelle', also Musterlösungen, belegt habe. Trotz diesen Schwierigkeiten glaube ich, dass ich von diesem Modul viel mitgenommen habe. 
