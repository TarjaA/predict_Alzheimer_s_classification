# Alzheimerin taudin vaiheen ennustaminen MRI-kuvien avulla

Projektin aiheena on kuvantunnistus ja Alzheimerin taudin vaiheen ennustaminen MRI-kuvan perusteella. Työssä on käytetty dataa, jossa on MRI-kuvia taudin kolmesta ensimmäisestä vaiheesta ja ei-dementoituneista aivoista. Seuraaviin kappaleisiin on kuvattu työn yleinen kulku ja perustelut projektissa tehdyille asioille. Koodin toiminnan yksityiskohtaisempi kuvaus löytyy sen kommentoinneista.

## Alzheimerin tauti

Alzheimerin tauti on hermoratoja ja aivosoluja vaurioittava parantumaton sairaus, joka johtaa muistin ja tiedonkäsittelyn heikentymiseen. Vauriot alkavat otsalohkosta edeten vähitellen aivokuorelle tuhoten muistin toimintaan liittyviä aivoalueita. (Juva 2018.) Taudin eteneminen jaetaan neljään vaiheeseen, jotka ovat varhainen, lievä, keskivaikea ja vaikea Alzheimerin tauti (Alzheimer etenee neljässä vaiheessa, N.d.). Taudin varhaisen vaiheen tyypillinen oire ovat muistihäiriöt, jotka voivat ilmetä lähimuistin toiminnassa ja kielellisessä ilmaisussa. (Juva 2018, Alzheimer etenee neljässä vaiheessa, N.d.) Todetun muistihäiriön syytä voidaan selvittää verikokeilla, neuropsykiatrisilla testeillä, aivosähkökäyrillä ja kuvantamistutkimuksilla (Miten Alzheimerin tauti tunnistetaan? N.d.).

Aivojen MRI-kuvissa Alzheimerista johtuvat muutokset voi havaita aivokammioiden suurentumisena, sekä aivokuoren ja hippokampuksena kutistumisena. Aivomassan väheneminen johtaa siten myös suurempiin väleihin poimujen välillä. (What causes dementia? N.d.). Datasetin keskivaikeasti dementoituneen MRI-kuvissa edellä mainitut muutokset voi huomata suurempina mustina alueina terveisiin aivoihin verrattuna (Kuvat 1 ja 2). Vaikka alla olevissa kuvissa ei ole tiedetty otetun kuvan tasoa ja kuvat eivät siten ole täysin vertailukelpoiset, voi maallikkokin nähdä eron terveiden ja dementoituneiden välillä mm. suurempina poimujen väleinä.
|||
|:---:|:---:|
|![MRI-kuva ei-dementoituneen aivoista](./Alzheimer_s_Dataset/train/NonDemented/nonDem400.jpg)|![MRI-kuva keskivaikeasti dementoituneen aivoista](./Alzheimer_s_Dataset/train/ModerateDemented/moderateDem35.jpg)|
*Kuva 1. Ei-dementoituneen aivot MRI-kuvassa.* |*Kuva 2. Keskivaikeasti dementoituneen aivot MRI-kuvassa.* 

## Datasetin valinta ja kuvaus

Data koostuu yhteensä 6400 mustavalkoisesta, kooltaan 208*176 kokoisesta MRI-kuvasta, jotka on datasetin kuvauksen mukaan käsin koottu eri lähteistä ja kuvien luokittelu verifioitu yksitellen. Datasetissä esiintyvät luokat ovat keskivaikeasti dementoitunut, lievästi dementoitunut, hyvin lievästi dementoitunut ja ei-dementoitunut. Kuvien taso yhden luokan sisällä vaihtelee ja tästä voi päätellä, että datasetissä esiintyy useampi kuin yksi kuva saman henkilön aivoista. Eri luokkien esiintyminen datassa on epätasaista, mikä todennäköisesti aiheuttaa ongelmia mallin luomisessa ja ennusteen tarkkuudessa. Datasetin kuvauksessa luokkien esiintymismääräksi oli ilmoitettu keskivaikeasti dementoituneita 62, lievästi dementoituneita 896, hyvin lievästi dementoituneita 2240 ja ei-dementoituneita 3200. Datasettiä tutkittaessa vastaavien lukumäärien todettiin hieman poikkeavan ja olevan todellisuudessa 64, 896, 2240 ja 3200. 

Datasetti on ollut valmiiksi jaettu opetus- ja testidataan, joka datamäärien jakautumisen perusteella vaikuttaisi olevan jaettu periaatteella 20 % testidataan ja 80 % opetusdataan. Datan jakamisessa on ilmeisesti huomioitu eri luokkien jakautuminen opetus- ja testidataan tasaisesti, minkä voi päätellä luokkien esiintymisestä opetus- ja testidatassa. Kuvausta opetus- ja testidataan jakamisesta ei kuitenkaan ollut annettu. Keskusteluosiossa Kagglen käyttäjät ovat kysyneet datan lähteitä ja luotettavuutta, mutta kysymyksiin ei ole saatu tyhjentäviä vastauksia. Kysymyksiin on vastattu yksinkertaisesti kuittaamalla, että datasetti on luotettava ja sitä voi käyttää tutkimustarkoituksiin, mutta perusteita ei oltu annettu.

## Kuvien lataaminen

Kuvien lataaminen tehtiin hakemalla ensin manuaalisesti datasetistä tehty zip-paketti ja purkamalla paketti paikallisesti projektikansioon. Datan lataamiseen ei katsottu tarvittavan omaa scriptiä, sillä kuvien lataus tehtiin vain kerran. Lisäksi datasetin kuvia haluttiin yleisesti silmäillä ennen datasetin käyttämistä. Kuvien silmäilyssä huomattiin, että osassa MRI-kuvista kontrasti oli selvästi heikompi kuin muissa. Huonomman kontrastin kuvia katsottiin kuitenkin olevan tasaisesti jokaisessa luokassa ja koska koulutettua mallia käytettäisiin myös huonolaatuisten kuvien luokittelun ennustamiseen, tulisi opetus- ja testidatassa myös olla huonompilaatuisia kuvia (Dodge, S. & Karam, L. 2016). Tyhjiä kuvia ei niitä silmäilemällä havaittu.

![Matala kontrasti](./Alzheimer_s_Dataset/test/VeryMildDemented/26%20(46).jpg)*Kuva 3. Matala kontrasti*

![Korkea kontrasti](./Alzheimer_s_Dataset/test/VeryMildDemented/26%20(51).jpg)*Kuva 4. Korkea kontrasti*

Kuvien lataamiseen Jupyter Notebookissa käytettiin OpenCV-kirjastoa ja scriptiä, jolla valmiiksi opetus- ja testidataan jaettu aineisto lisättiin omaan taulukkoon ennustettavan muuttujan kanssa. Ennustettava muuttuja lisättiin numeerisena arvona datasetin kansiojaottelun mukaan: keskivaikeasti dementoitunut 3, lievästi dementoitunut 2, hyvin lievästi dementoituneita 1 ja ei-dementoitunut 0. Luodusta taulukosta tehtiin myöhemmin dataframe, josta jako opetus- ja testidataan voitiin tehdä uudelleen. 

Kuvien lataamisen yhteydessä kuvat rajattiin koosta 208x176 neliöksi kokoon 176x176, jotta neuroverkon rakentamisessa ei päädyttäisi hankaliin kokoihin mm. feature-matriisien koon maxpooling-kerrosten määrityksen kanssa. Rajauksella helpotettiin lisäksi muistin kuormaa, mutta kuvien skaalausta pienemmiksi ei haluttu tehdä, sillä erot kuvien välillä näyttivät olevan pieniä ja ennusteen tarkkuutta ei haluttu tällä tavoin huonontaa. Mahdollisesti kuvia olisi voinut rajata hieman enemmänkin, mutta kuvien muokkauksessa ei haluttu ottaa sitä riskiä, että jokin oleellinen osa rajautuisi pois ja rajattujen kuvien koossa oli päästy kahdella jaolliseen lukuun. Verrattuna muilla kursseilla käytettyihin kuvakokoihin, koon 176x176 ei myöskään pitäisi olla liian suuri neuroverkon koulutusta ajatellen. (Pinetz, T. 2017.)

## Datan esikäsittely ja muokkaaminen

Datan esikäsittely tehtiin kuvien rajauksen ja laaduntarkastelun osalta kuvien lataamisen yhteydessä. Lataamisen jälkeen esikäsittelyä jatkettiin tarkistamalla, onko datasetissä identtisiä kuvia. Tämän jälkeen tehtiin datan jako uudelleen opetus- ja testidataan train_test_split -funktiolla. Koska datasetissä kuvien määrä eri luokkien välillä oli epätasaisesti jakautunut, käytettiin funktiossa stratify-parametria, jotta opetus- ja testidataan tulisi eri luokkien kuvia oikeassa suhteessa.

Opetus- ja testidataan jakamisen jälkeen taulukot muutettiin konvoluutioneuroverkolle kelvolliseen muotoon ja kuvien pikseleiden arvot skaalattiin minimi-maksimi-skaalauksella välille 0-1. Muodon muuttamisessa käytettiin reshape-funktiota ja parametrien arvoina annettiin kuvien määrä, korkeus, leveys ja värikanava. Datan skaalaus puolestaan tehtiin jakamalla arvot luvulla 255. Luokittelevalle neuroverkolle ennusteiden täytyy olla onehot-muodossa, joten y-muuttujista tehtiin vielä dummy-muuttujat pandasin get_dummies -komennolla.

## Neuroverkon rakentaminen ja koulutus

Neuroverkon rakentamiseen käytettiin konvoluutioneuroverkkoa, jonka tiedettiin toimivan paremmin kuvantunnistuksessa kuin MLP-neuroverkon. Verkon rakentaminen aloitettiin lisäämällä neuroverkkoon ensin vain muutama konvoluutio- ja maxpooling-kerros, joilla testattiin, että tehty verkko ylipäätään toimii ja sitä voidaan kouluttaa. Tämän jälkeen lisättiin konvoluutio-, maxpooling- ja dense-kerrosten määrää siten, että malliin tuli yhteensä 4 konvoluutio- ja maxpooling-kerrosten yhdistelmää. Piilotettujen kerrosten aktivaatiofunktiona käytettiin ReLu-funktiota, sillä dementialuokituksen ja MRI-kuvissa näkyvien mustien alueiden välisen suhteen arveltiin olevan lineaarista. Neuroverkon ulostulokerroksessa käytettiin Softmax-funktiota, jota voi käyttää luokitteluongelmissa verkon viimeisenä kerroksena. Toisella mallilla päästiin jo yli prosentin tarkkuuteen validaatiodatassa, ja tämän pohjalta lähdettiin tekemään pieniä muutoksia verkon rakenteeseen ja opetuksessa käytettäviin parametreihin.

Toisen mallin tarkkuutta kokeiltiin ensin parantaa muuttamalla learning rate-parametria, lisäämällä opetuskierrosten (epoch) määrää ja vaihtamalla painokertoimien päivitystiheyttä (batch size). Parhaimmillaan päästiin n. 95%:n tarkkuuteen ja malli vaikutti tuottavan tasaisesti samanlaisen tuloksen koulutettiinpa sitä miten monella kierroksella tai erämäärällä tahansa. Malli näytti myöskin tuottavan samanlaisen tarkkuuden sekä opetus- että testidatassa. Lisäämällä tähän malliin vielä lisää konvoluutio-, maxpooling- ja dense-kerroksia, päästiin validaatiodatassa satunnaisesti 98,05%:n tarkkuuteen. Tämän neuroverkko näkyy kuvassa 7 lopullisen ja poiskommentoitujen kerrosten yhdistelmänä. Koulutuksen aikana saattoi havaita, että verkolla oli taipumusta ylioppimiseen. Opetusdatassa päästiin helposti sadan prosentin tarkkuuteen, mutta testidatassa tarkkuus jäi usein 93-96 prosentin tasolle.

Verkon ylioppimista lähdettiin korjaamaan yksinkertaistamalla verkkoa ja lisäämällä Dropout-kerros dense-kerrosten väliin, jolla deaktivoitiin 20% verkon neuroneista. Tällä onnistuttiin kuitenkin vain huonontamaan tarkkuutta, joten seuraavaksi kokeiltiin L2 regularisaatiota kerneliin, biasiin ja aktivaatiofunktioon. L2 regularisaation vaikutusta seuratiin piirtämällä opetus- ja testidatan tarkkuuksista kuvaajat, joita on esitetty kuvissa 5 ja 6. L2 regularisaation lisäämisellä kerneliin ei havaittu olevan vaikutusta. Biasiin lisättynä opetus- ja testidatan tarkkuuksia saatiin lähemmäs toisiaan, mutta tämä johtui huonommasta tarkkuudesta opetusdatassa. Aktivaatiofunktioon lisättynä tarkkuus parani testidatassa muutamalla prosentilla. Uteliaisuudesta kokeiltiin lisätä vielä toinen L2 regularisaatio toisen dense-kerroksen aktivaatiofunktioon, minkä todettiin parantaneen tarkkuutta edelleen. Lisättynä kolmanteen dense-kerrokseen tarkkuus lähti jälleen huonontumaan, ja lopullisesta mallista tiputettiin yksi dense-kerros pois.

![L2 regularisaatio kerneliin kuvaaja](./muut_kuvat/l2_regularisaatio_kernel_kuvaaja.PNG)*Kuva 5. L2 regularisaatio kerneliin.*

![L2 regularisaatio aktivaatiofunktioon kuvaaja](./muut_kuvat/l2_regularisaatio_activity_1_kuvaaja.PNG)*Kuva 6. L2 regularisaatio aktivaatiofunktioon.*

![Neuroverkon lopullunen rakenne](./muut_kuvat/l2_regularisaatio_9906.PNG)*Kuva 7. Neuroverkon lopullinen rakenne*


## Ennustuksien vertailutestidataan

Neuroverkon koulutuksen aikana mallin hyvyyttä seurattiin tulostamalla tarkkuus testidatassa jokaisen epookin jälkeen (verbose). Kun koulutuksessa oli päästy tyydyttävään tarkkuuteen, arvioitiin mallia myös muilla mittareilla, sillä erityisesti epätasaisesti jakautuneessa datassa tarkkuus ei välttämättä kerro koko totuutta mallin hyvyydestä. Ensimmäisenä testidatan ennustettavista arvoista ja mallin antamista ennusteista tehtiin sekaannusmatriisi, josta näkyy kuinka hyvin malli on osannut ennustaa tietyn luokan arvoja. Kuvassa 8 on sekaannusmatriisi testidatan arvoista, riveillä esitetään luokat ja sarakkeissa mallin ennuste. Matriisin ensimmäinen rivi ovat järjestyksessä lievimmästä diagnoosista vaikeimpaan siten, että luokka "ei-dementoitunut" on ensimmäinen ja viimeinen "keskivaikeasti dementoitunut".

![Sekaannusmatriisi testidatan arvoista](./muut_kuvat/confusion_matrix.PNG)*Kuva 8. Sekaannusmatriisi testidatan tuloksista*

Sekaannusmatriisista huomaa, että malli osaa suhteellisen hyvin ennustaa MRI-kuvista dementian oikean luokittelun, mutta yksittäisten kuvien kohdalla ennuste on mennyt pieleen. Toisessa luokassa "hyvin lievästi dementoitunut" arvoja on virheellisesti luokiteltu enemmän ei-dementoituneisiin, kuin muiden luokkien kohdalla. Yksi mahdollinen selitys tälle on se, että hyvin lievä dementia ei välttämättä vielä näy aivoissa ja siten malli on luokitellut MRI-kuvan ei-dementoituneisiin. Dementian diagnosointiin on voitu käyttää myös muita arviointikriteerejä, eikä luokittelua ole alun perin tehtykään MRI-kuvan perusteella. Vastaavasti sekaannusmatriisin ensimmäisellä rivillä näkyy ei-dementoituneita luokitellun lievästi dementoituneisiin, missä voi olla taustalla esimerkiksi jonkin muun sairauden tai vamman tuottama vaurio aivoihin. 

Terveyteen liittyvissä kysymyksissä mallin olisi toivottavaa luokittelevan sairaus mieluummin vakavampaan suuntaan ja antavan ennemmin vääriä positiivisia tuloksia, kun vääriä negatiivisia tuloksia. Tällöin potilas voitaisiin ohjata jatkotutkimuksiin eikä sairaus jäisi hoitamatta. Sekaannusmatriisissa tällainen tilanne näkyisi väärinä luokituksina matriisin diagonaalin yläpuolella, kun taas väärät luokittelut näyttävät nyt painottuvan diagonaalin alapuolelle. Mallilla on siis taipumusta luokitella taudin kuva lievempään suuntaan vakavamman sijaan. Kyseisen aiheen kohdalla voi kuitenkin miettiä, kannattaako mallia lähteä korjaamaan, sillä taudin diagnoosi ei perustu ainoastaan MRI-kuviin ja aivojen kuvantaminen lienee diagnosoinnissa viimeisimpiä lisätutkimuksia. Luokittelu vakavampaan suuntaan ei siis välttämättä ohjaisi potilasta lisätutkimuksiin, vaan seuraus voisi olla vaikkapa väärä lääkitys.

Sekaannusmatriisin tuloksia voi kuitenkin pitää yleisesti hyvinä, sillä malli on tasaisesti osannut ennustaa oikeita luokitteluja eri vaihtoehtojen kesken. Kun sekaannusmatriisista laskee muita mallin hyvyyttä mittaavia tunnuslukuja, voi näidenkin todeta olevan tyydyttävällä tasolla. Alle on esimerkkinä laskettu luokille Ei-dementoitunut ja Hyvin lievästi dementoitunut recall-, precision- ja F1-arvoja sekaannusmatriisissa esitetyistä luvuista. Pyöristetyt arvot on esitetty taulukossa 1 muiden tunnuslukujen kanssa. Recall ja precision -arvoilla pyritään vastaamaan kysymyksiin "Kuinka suuri osuus tietyn luokan MRI-kuvista sai oikean ennusteen?" ja "Kuinka suuri osuus luokkaan ennustetuista kuvista oli oikein ennustettu?". F1-arvo puolestaan on recall- ja precision-arvoista laskettu harmoninen keskiarvo. 

-  Ei-dementoitunut: 
    - recall: 637/(637+3)=0,9953...=99,53%
    - precision: 637/(637+7+1)=0,9876...=98,76%
    - F1: (2x0,9953x0,9876)/(0,9953+0,9876)=0,9914...=99,14%

- Hyvin lievästi dementoitunut:
    - recall: 441/(441+7)=0,9844...=98,44%
    - precision: 441/441=1=100%
    - F1: (2x0,9844x1)/(0,9844+1)=0,9921...=99,21%

![](./muut_kuvat/classification_report.png)*Taulukko 1. Tunnuslukujen kooste*

Edellä esitetyistä arvoista on suotavampaa seurata luokkien recall-arvoja, kuin ennustuksen tarkkuutta. Kuten aikaisemmin mainittiin, potilaan kannalta on parempi, että useampi ohjataan tutkimuksiin kuin jätetään tutkimatta. Aineiston luokista Keskivaikeasti dementoituneissa ennusteen tarkkuus jää toivottua pienemmäksi, mutta onnistumisprosenttiin vaikuttanee vahvasti datan vähyys. Pienellä testidatalla jo yksikin väärin ennustettu kuva laskee merkittävästi ennusteen prosentuaalista tarkkuutta, kuten tässä on käynytkin. Taulukossa 1 esitetyistä arvoissa macro avg -arvo on painottamaton keskiarvo, joka huomioi kustakin luokasta erikseen lasketun F1-arvon. Painotettu keskiarvo puolestaan on painotettu keskiarvo kunkin luokan F1-arvoista. (Mohajon J. 2020.) Epätasapainoisen datan tapauksessa kannattanee enemmän huomioida painotettua keskiarvoa kuin macro-arvoa. 

## Yhteenveto

Projektin data etsittiin Kagglesta suodattaen tarjolla olevia datasettejä ensin kuvien määrän, sekä muiden käyttäjien tekemien käytettävyysarvioiden ja luokituksen perusteella. Lopulliseen aiheen valintaan vaikuttivat myös oma kiinnostus ja Alzheimer-datasetin haastavuus: MRI-kuvien perusteella Alzheimerin taudin toteaminen on asiaan perehtymättömälle ihmisellekin vaikeaa, joten kuinka mahtaa onnistua luokitteluun tehdyllä mallilla? Neuroverkon koulutuksessa päästiin odotettua parempaan lopputulokseen, jota olisi mahdollisesti voinut vielä korjata taudin aikaisen diagnosoinnin kannalta suotuisempaan suuntaa. Lisäksi työtä olisi voinut jatkaa tutkimalla mallin tehokkuutta tai keinoja sen hienosäätämiseksi. Yksi mahdollinen keino olisi ollut tarkastella mallin parametreja ja yrittää optimoida näitä paremman ja tarkemman mallin aikaan saamiseksi.Edellä mainitun ohella olisi ollut mielenkiintoista testata mallin toimivuutta mahdollisesti muista lähteistä löytyneisiin MRI-kuviin.

## Videoseminaari

Video on jaettu Streamiin Janne Alatalolle. https://web.microsoftstream.com/video/bc9d51ed-760d-438c-8d6f-81769e08dd82

## Lähteet

Alzheimer etenee neljässä vaiheessa. N.d. Kuvaus Alzheimerin taudin vaiheista Alzheimerinfo.fi-sivustolla. Viitattu 29.3.2021. https://alzheimerinfo.fi/alzheimerin-tauti/alzheimer-etenee-neljassa-vaiheessa/

Dodge, S. & Karam, L. Understanding How Image Quality Affects Deep Neural Networks. 2016. Arizonan yliopiston artikkeli kuvan laadun vaikutuksesta neuroverkon toimintaan. Viitattu 18.4.2021. https://arxiv.org/pdf/1604.04004.pdf

Juva, K. Alzheimerin tauti. 30.7.2018. Artikkeli Alzheimerin taudista Duodecim Terveyskirjasto -sivustolla. Viitattu 29.3.2021. https://www.terveyskirjasto.fi/dlk00699

Miten Alzheimerin tauti tunnistetaan? N.d. Artikkeli Alzheimerin taudin diagnosoinnista Alzheimer.fi-sivustolla. Viitattu 29.3.2021. https://alzheimerinfo.fi/alzheimerin-tauti/miten-alzheimerin-tauti-tunnistetaan/

Mohajon J. 2020. Confusion Matrix for Your multi-Class Machine Learning Model -artikkeli Towards data Science -sivustolla. Viitattu 20.4.2021. https://towardsdatascience.com/confusion-matrix-for-your-multi-class-machine-learning-model-ff9aa3bf7826

Pinez, T. Do image have to have the same size for deep learning? 2017. Vastaus Stackoverflow-sivustolla esitettyyn kysymykseen. Viitattu 18.4.2021. https://stackoverflow.com/questions/42648326/do-image-have-to-have-the-same-size-for-deep-learning#:~:text=1%20Answer&text=Normally%20for%20deep%20learning%20this,applied%20on%20all%20image%20sizes.&text=To%20choose%20a%20good%20image,give%20you%20better%20accuracy%20normally

What causes dementia? N.d. Viitattu 30.3.2021. https://qbi.uq.edu.au/dementia/dementia-causes-and-treatment

