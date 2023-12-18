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

Im Ersten Handlungsziel haben wir die Infrastruktur eingerichtet, die InsecureApp heruntergeladen, gestartet und den Aufbau der App angeschaut. Dann haben wir einige wichtige Grundbegriffe zusammen angeschaut, welche für den Verlauf vom Modul wichtig waren, wie Zum Beispiel ```vertraulichkeit```, ```Integrität``` und ```Verfügbarkeit```. Wir haben einige Szenarien bekommen und mussten anordnen, wie hoch diese Schutzziele betroffen waren. Danach haben wir ```Open Web Application Security Project```, kurz ```OWASP``` angeschaut, eine Security Website. 

Beim Praktischen Teil, Auftrag ```LA_183_10_Business_Logic```, mussten wir bei der App den Newseintrag Security verändern. Der Fehler war derjenige, dass jeder, wer die ID des News Eintrags kennt, dieser bearbeiten oder löschen kann. Der Benutzer / die Zugriffsrechte werden im Backend nicht geprüft. Dies mussten wir so umprogrammieren, dass der normale Benutzer nur noch ihre eigenen News bearbeiten und löschen kann.

Artefakt: Codeabschnitt?
Folgende Änderungen wurden im Code gemacht:

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

```


## **_Handlungsziel 2_**


## **_Handlungsziel 3_**


## **_Handlungsziel 4_**


## **_Handlungsziel 5_**


## Selbsteinschätzung des Erreichungsgrades der Kompetenz des Moduls
Geben Sie eine Selbsteinschätzung zu der Kompetenz in diesem Modul ab. Schätzen Sie selbst ein, inwiefern Sie die Kompetenz dieses Moduls erreicht haben und inwiefern nicht. Es geht in diesem Abschnitt nicht darum, auf die einzelnen Handlungsziele einzugehen. Das haben Sie bereits gemacht. Begründen Sie ihre Aussagen.
