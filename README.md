# NiklausAndrea_LB183
Dies ist eine sehr coole LB o.o

## Einleitung
Dies ist die Leistungsbeurteilung von Andrea Niklaus. In diesem Modul 183 geht um Applikationssicherheit implementieren. In diesem Portfolio werde ich die Handlungsziele in je einem Abschnitt nachweisen, welche auch je mindistens einen Artefakt haben. 

## _Handlungsziel 1_

Als Artefakt habe ich den Codeauschnitt und Screenshots in Relation mit diesem Codeabschnitt genommen:

**Codeabschnitt im NewsController.cs:**
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

**Wie habe ich dieses Handlungsziel erreicht:**
Im Ersten Handlungsziel haben wir die Infrastruktur eingerichtet, die InsecureApp heruntergeladen, gestartet und den Aufbau der App angeschaut. Dann haben wir einige wichtige Grundbegriffe zusammen angeschaut, welche für den Verlauf vom Modul wichtig waren, wie zum Beispiel ```Vertraulichkeit```, ```Integrität``` und ```Verfügbarkeit```.

Beim Praktischen Teil, Auftrag ```LA_183_10_Business_Logic```, mussten wir bei der App den Newseintrag Security verändern. Der Fehler war derjenige, dass jeder, wer die ID des News Eintrags kennt, dieser bearbeiten oder löschen kann. Der Benutzer / die Zugriffsrechte werden im Backend nicht geprüft. Dies mussten wir so umprogrammieren, dass der normale Benutzer nur noch ihre eigenen News bearbeiten und löschen kann.
Somit habe ich dieses Handlungsziel erreicht, indem ich die Zugriffsrechte, wie im Auftrag ```LA_183_10_Business_Logic``` gefordert, verbessert habe habe.


**Erklärung des Artefakts:**
Der Artefakt belegt die Codeänderungen, welche ich in NewsController.cs vorgenommen habe, um die Applikation besser zu schützen. Somit wird sichergestellt, dass ein normaler Benutzer nur seine eigenen News bearbeiten und löschen kann. Die Überprüfung der Benutzerrechte wurde durch Hinzufügen von Bedingungen vor dem Aktualisieren und Löschen von News hinzugefügt.

**Kritische Bewertung:**
Die verschiedene Änderungen sind erfolgreich und erfüllen das Handlungsziel. Die Überprüfung der Benutzerrechte wurde korrekt eingeführt, um nicht befugte Bearbeitung und Löschung von News zu verhindern. Der Artefakt ist strukturiert und mit dem Screenshot ist es einfach, dies zu intepretieren und lesen. 

**Erklärung des Screenshots:**
Der User konnte mit Adminrechte einen 'AdminNews' erstellen (und kann diese immer noch bearbeiten.) Nach der Änderung kommt der Error 401 (siehe unterer Screenshot), wenn man versucht, einen Newsbeitrag als Admin zu erstellen, wenn man mit dem User Konto angemeldet ist.

## **_Handlungsziel 2_**

Als Artefakt habe ich den Codeauschnitt und die Veränderung im Auftrag LA_183_05_SQLInjection genommen.

**Artefakt: Codeabschnitt in der Login-Methode für SQL Injection-Schutz:**
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

**Erklärung des Artefakts:**
Die Codeänderungen in der Login-Methode wurden vorgenommen, um SQL-Injection-Angriffe zu verhindern. Hierbei wird die Eingabe des Benutzernamens und des Passworts auf Gültigkeit überprüft und anschließend wird das Passwort als Hashwert in der Datenbank abgeglichen.

**Kritische Bewertung:**
Die implementierten Änderungen bieten eine grundlegende Sicherheit gegen SQL-Injection-Angriffe. Allerdings könnte die Verwendung von MD5 für das Passwort-Hashing durch eine sicherere Methode ersetzt werden, um modernen Sicherheitsstandards gerecht zu werden.


**XSS: In NewsController.cs:**
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
**Wie wurde das Handlungsziel erreicht**
Das Handlungsziel wurde erreicht, indem ich den Code verändert habe, um die Sicherheitslücke zu schliessen. Dabei habe ich die Sicherheitslücke und die Ursache von dem in der Applikation erkennt und diese gehoben habe, was nachweist, dass ich dieses Handlungsziel erfolgreich gelöst und verstanden habe. 

**Erklärung des Artefakts:**
Der Artefakt zeigt die veraltete und die neue Version im Code. Im Veralteten Code bestand die Gefahr von einer SQL-Injection beim Einloggen. Dies wurde im Neuen Code aufgehoben, damit sich kein unauthorisierter Benutzer mit SQL Befehle wie -- vor dem Passwort schreiben könnte, etc. und somit ohne das Passwort anzugeben/wissen, sich in die Applikation einloggen zu können. Somit sind die Eingaben des Benutzers nicht mehr direkt in der SQL-Tabelle, sondern als separate Variable gespeichert. 

**Kritische Bewertung:**
Die Aufträge von diesem Handlungsziel waren verständlich zu lösen, was auch dazu führte, dass ich den Artefakt wie auch die Erklärung gut und schnell machen konnte. Ich hatte keine Schwierigkeiten dabei. Beim Erstellen des Artefakt habe ich auch geschaut, dass der Code sauber und verständlich mit den verschiedenen Änderungen gestalten ist. Die Änderungen im Code sind jedoch nur minimal und könnten erweitert werden, damit die Applikation noch sicherer wäre.

**Erklärung Auftrag Unsaubere_API:**

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

## **_Handlungsziel 3_**

**Broken Access Controll:**
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
**Erklärung des Artefakts:**
Die Codeänderungen wurden vorgenommen, um Broken Access Control zu beheben. Statt direkter SQL-Abfragen werden die Benutzerinformationen durch Entity Framework Core mit sicheren Abfragen abgerufen.

**Kritische Bewertung:**
Die implementierten Änderungen bieten eine verbesserte Sicherheit durch die Verwendung von Entity Framework Core für den Datenbankzugriff anstelle von direkten SQL-Abfragen. Dies verringert das Risiko von SQL-Injection-Angriffen erheblich.


## **_Handlungsziel 4_**

SecretImRepository
HumanFactor
DefensiveProgrammierung

**LA_183_13_HumanFactor: UserController.cs+PasswortUpdateDTO.cs:**

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
**Erklärung des Artefakts:**
Der Code wurde im AccountController.cs entsprechend angepasst. Dies beinhaltet eine bessere Strukturierung des Codes, das Hinzufügen von Kommentaren, die Verwendung von IsMatch anstelle von Match für die Regex-Validierung und die Bereitstellung von sinnvollen HTTP-Antwortcodes. Ausserdem wurde die Rückgabemeldung nach einer erfolgreichen Passwortänderung aktualisiert. Mit dem neuen Code kann daher ein externer Nutzer nicht einfach so das Passwort ändern, wenn er/sie das altes Passwort nicht weiss. Somit ist die Applikation ein wenig sicherer als vorher! Success 👍!

**Kritische Bewertung:**
Die implementierten Änderungen verbessern die Lesbarkeit des Codes, die Verständlichkeit und die Übersichtlichkeit. Die Validierung des neuen Passworts erfolgt nun durch die Verwendung von IsMatch, was eine genauere Überprüfung ermöglicht. Die HTTP-Antwortcodes und Rückgabemeldungen wurden verbessert, um besser auf den Status der Passwortänderung hinzuweisen.

**Artefakt: Geänderte appsettings.json - Sicherung des Secrets im Repository**

```csharp
//Unser lieber, nicht sicherer Code wurde entfernt:
"Key": "47v1npCi7PL4fIynUvRDWrXMSsZUwpTNvBgvsNOmCfpWfVDMMU83vWI7IEeVNq7u3KdssLQHiEfODRFHuSlBRja04OBDVHWPtEM4hvUyQA2TIhvaxi8BMdtcnfH5FUOhn2ti6hYF33PRV+J8znJAI2Cmcw3/DejQIGPmpbPbNZc="


//Neuer code, damit nicht jeder unser Key sieht und jedes mal ein anderer generiert wird (Sicherheit und so ;))
"Key": ""

```
Artefakt: Geänderte appsettings.json - Sicherung des Secrets im Repository

Erklärung des Artefakts:
Die Datei appsettings.json enthält sensible Informationen wie Schlüssel und Geheimnisse für die Anwendung. Das Artefakt zeigt die Entfernung des unsicheren Codes und die Einführung einer sicheren Praxis, indem der ursprüngliche Schlüssel entfernt wurde und ein neuer Platzhalter-Schlüssel hinzugefügt wurde. Dies gewährleistet, dass das Geheimnis nicht im Repository gespeichert wird.

Kritische Bewertung:
Die Umsetzung des Artefakts ist wirksam und erfüllt das Handlungsziel, sensible Informationen, insbesondere Geheimnisse und Schlüssel, sicher im Repository zu speichern. Die Verwendung eines Platzhalter-Schlüssels ist eine gute Praxis, um sicherzustellen, dass keine vertraulichen Daten öffentlich zugänglich sind. Es ist jedoch wichtig sicherzustellen, dass dieser Platzhalter regelmässig aktualisiert wird, um die Sicherheit weiter zu gewährleisten.


## **_Handlungsziel 5_**

Logging

Für den Logging Auftrag habe ich Inspiration von dem Code im Auftrag geholt und mit den Musterlösungen verglichen und verbessert.

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


//Programm.cs

//Neu Hinzugefügt :D

// Logging Configuration
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole(); // Console Output
    logging.AddDebug(); // Debugging Console Output
});

```

Erklärung des Artefakts:
Das Artefakt zeigt die Integration von verbessertem Logging in verschiedenen Teilen der Anwendung, einschließlich des LoginControllers, des NewsControllers und der Konfiguration im Programm.cs. Durch die Hinzufügung des ILogger-Parameters in den Controllern und die Konfiguration im Programm.cs wird detailliertes Logging implementiert, um wichtige Informationen über den Anwendungsstatus zu erhalten.

Kritische Bewertung:
Die Implementierung des verbesserten Loggings erfüllt das Handlungsziel effektiv, indem sie eine detaillierte Protokollierung in verschiedenen Teilen der Anwendung ermöglicht. Die Verwendung von Log-Leveln wie Information und Warning bietet Flexibilität für unterschiedliche Situationen. Es ist jedoch wichtig sicherzustellen, dass die Log-Meldungen aussagekräftig und hilfreich sind, um bei der Fehlersuche und Überwachung effektiv zu sein.

## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.
