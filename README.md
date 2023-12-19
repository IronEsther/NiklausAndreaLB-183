# NiklausAndrea_LB183
Dies ist eine sehr coole LB o.o

Sie arbeiten das Modul durch und weisen mit einem ePortfolio die erreichten Handlungsziele mit eigenen Beispielen von Artefakten (hergestellte Objekte / Produkte) nach. Sie weisen somit in dieser Leistungsbeurteilung nach, welche Handlungsziele Sie in welchem Masse erreicht haben. 

Sie erstellen zu den einzelnen Handlungszielen Artefakte (hergestellte Objekte / Produkte), anhand denen Sie beweisen können, dass Sie das Handlungsziel erreicht haben. Sie können dazu die abgegebene Applikation verwenden oder ‒ in Absprache mit der Lehrperson ‒ ein Beispiel aus Ihrer Firma oder aus dem Lernatelier. Anhand dieser Applikation weisen Sie mehrere oder sogar alle Handlungsziele nach.

Sie dürfen die selbst erarbeiteten Resultate der Aufträge im Modul als Artefakte übernehmen.


## Einleitung
In der Einleitung beschreiben Sie kurz den Inhalt des ePortfolios, damit die Lesenden einen Überblick haben, was sie erwartet.

Dies ist die Leistungsbeurteilung von Andrea Niklaus. Jeder Abschnitt beinhaltet jeweils ein Handlungsziel. Dieses Modul geht um Applikationssicherheit implementieren. Ich werde in diesem Portfolio Ihnen mit Artefakte zeigen, was ich mitgenommen habe. 

## Abschnitt pro Handlungsziel
Pro Handlungsziel ist ein Abschnitt mit folgendem Inhalt zu erstellen:

1. Wählen Sie ein Artefakt, welches Sie selbst erstellt haben und anhand dem Sie zeigen können, dass Sie das Handlungsziel erreicht haben.

2. Weisen Sie nach, wie Sie das Handlungsziel erreicht haben. Verweisen Sie dabei auf das von Ihnen erstellte Artefakt. Das Artefakt muss im ePortfolio sichtbar oder verlinkt sein.

3. Erklären Sie das Artefakt in wenigen Sätzen. Sollte das Artefakt mehrere Handlungsziele beinhalten dürfen Sie die Erklärung auch zusammenfassen.

4. Beurteilen Sie die Umsetzung Ihres Artefakts im Hinblick auf das Handlungsziel kritisch. Sollten gewisse Aspekte des Handlungsziels fehlen, haben Sie die Möglichkeit, in diesem Teil darauf einzugehen.

## _Handlungsziel 1_

**Artefakt: Codeabschnitt im NewsController.cs:**

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
**Erklärung des Artefakts:**
Die Codeänderungen im NewsController.cs wurden vorgenommen, um sicherzustellen, dass ein normaler Benutzer nur seine eigenen News bearbeiten und löschen kann. Die Überprüfung der Benutzerrechte wurde durch Hinzufügen von Bedingungen vor dem Aktualisieren und Löschen von News implementiert.

**Begründung der Erreichung vom Handlungsziel 1:**

Im Ersten Handlungsziel haben wir die Infrastruktur eingerichtet, die InsecureApp heruntergeladen, gestartet und den Aufbau der App angeschaut. Dann haben wir einige wichtige Grundbegriffe zusammen angeschaut, welche für den Verlauf vom Modul wichtig waren, wie Zum Beispiel ```vertraulichkeit```, ```Integrität``` und ```Verfügbarkeit```.

Beim Praktischen Teil, Auftrag ```LA_183_10_Business_Logic```, mussten wir bei der App den Newseintrag Security verändern. Der Fehler war derjenige, dass jeder, wer die ID des News Eintrags kennt, dieser bearbeiten oder löschen kann. Der Benutzer / die Zugriffsrechte werden im Backend nicht geprüft. Dies mussten wir so umprogrammieren, dass der normale Benutzer nur noch ihre eigenen News bearbeiten und löschen kann.
Somit habe ich dieses Handlungsziel erreicht, indem ich die Zugriffsrechte, wie im Auftrag ```LA_183_10_Business_Logic``` gefordert, verbessert habe habe.

**Kritische Bewertung:**
Die implementierten Änderungen sind wirksam und erfüllen das Handlungsziel erfolgreich. Die Überprüfung der Benutzerrechte wurde korrekt eingeführt, um unbefugte Bearbeitung und Löschung von News zu verhindern.

**Beweis der Durchführung (Screenshot):**
Der User konnte mit Adminrechte einen 'AdminNews' erstellen (und kann diese immer noch bearbeiten.) Nach der Änderung kommt der Error 401 (siehe unterer Screenshot), wenn man versucht, einen Newsbeitrag als Admin zu erstellen, wenn man mit dem User Konto angemeldet ist.


## **_Handlungsziel 2_**

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

    if (user == null)
    {
        return Unauthorized("login failed");
    }

    return Ok(CreateToken(user));
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
**Erklärung des Artefakts:**
Die Codeänderungen wurden vorgenommen, um einen XSS-Schutz zu implementieren. Durch Verwendung von HttpUtility.HtmlEncode wird sichergestellt, dass potenziell schädlicher HTML-Code in den News-Headern und -Details korrekt kodiert wird, bevor sie in die Datenbank geschrieben werden.

**Kritische Bewertung:**
Die implementierten Änderungen bieten eine wirksame Schutzmaßnahme gegen XSS-Angriffe, indem verhindert wird, dass nicht vertrauenswürdiger HTML-Code in den News-Headern und -Details gespeichert wird.

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

```json
appsettings.json
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
Zusätzliche Lern-Arbeitsaufträge:
AuditTrail

## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.
