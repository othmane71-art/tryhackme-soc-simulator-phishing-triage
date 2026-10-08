# TryHackMe SOC Simulator – Phishing Triage Lab (Splunk)

> Rapport de pratique d'un analyste SOC L1 : triage de 4 alertes de phishing sur l'environnement fictif **The Try Daily**.

## 1. Objectifs

- Appliquer le playbook de triage : assign → comprendre la règle → investiguer dans le SIEM → enrichir (threat intel) → classifier → rapporter → escalader.
- Corréler les sources **Email** et **Firewall** dans **Splunk**.
- Rédiger des rapports de cas exploitables (qui, quoi, quand, où, IOC, remédiation).

## 2. Environnement

| Élément | Détail |
|---|---|
| Plateforme | TryHackMe SOC Simulator |
| SIEM | Splunk (Search & Reporting) |
| Sources de logs | Email, Firewall |
| Threat intel | TryDetectThis (Analyst VM) |
| Réseau interne | Office 10.20.2.0/24 |
| Date des alertes | 08.10.2026, 18:57 – 19:05 |

## 3. Méthodologie

1. **Choisir** l'alerte non assignée la plus ancienne (priorité à la sévérité).
2. **Assigner** et passer en *In Progress* pour éviter le travail en double.
3. **Comprendre** la règle : que détecte-t-elle, qui est visé, quels IOC ?
4. **Investiguer** dans Splunk : pivot sur le domaine, l'expéditeur, l'IP et l'utilisateur, puis construire la timeline.
5. **Enrichir** les IOC avec TryDetectThis.
6. **Classifier** (TP / FP) et décider de l'escalade : une escalade est nécessaire si une remédiation est requise ou si l'alerte appartient à une chaîne d'attaque.
7. **Rapporter** puis fermer le cas.

### Requêtes Splunk utilisées

```spl
index=* "<domaine ou IOC>" | sort _time
index=* sender="<expéditeur>" | stats count by recipient, subject
index=* (dest_ip="<IP>" OR "<domaine>") | stats count by src_ip, action, url
index=* ("<utilisateur>" OR <IP interne>) | sort _time
```

**Logique SOC :** un pivot sur l'IOC montre à la fois *qui a reçu* (email) et *qui a cliqué* (firewall). Le champ `action` (allowed / blocked) décide de l'impact.

## 4. Synthèse des alertes

| ID | Règle | Utilisateur | Verdict | Escalade |
|---|---|---|---|---|
| 8814 | Inbound Email Containing Suspicious External Link | Julia Garcia | False Positive | Non |
| 8815 | Inbound Email Containing Suspicious External Link | Hannah Harris | True Positive | Non |
| 8816 | Access to Blacklisted External URL Blocked by Firewall | Hannah Harris | True Positive | Non |
| 8817 | Inbound Email Containing Suspicious External Link | Charlotte Allen | True Positive | **Oui** |

## 5. Analyses détaillées

### 5.1 Alerte 8814 – Onboarding hrconnex.thm (False Positive)

**Timeline**

| Heure | Événement |
|---|---|
| 18:57:21 | Mail de `onboarding@hrconnex.thm` vers `j.garcia` |
| 18:58:54 | Les RH (H. Harris) informent l'IT que hrconnex.thm est le nouveau partenaire RH tiers |
| 19:03:20 | Mail renvoyé à `j.garcia` |

**Logique SOC :** le lien externe a déclenché la règle, mais le domaine est confirmé par une demande interne, TryDetectThis le classe **CLEAN**, et aucune connexion vers lui n'apparaît dans le firewall.

**Rapport**
- **Time of activity:** 08.10.2026, 18:57 – 19:03
- **Affected entities:** Julia Garcia (win-3452, 10.20.2.8)
- **Classification:** False Positive
- **Escalade:** non requise
- **Remédiation:** ajouter hrconnex.thm à la liste des domaines autorisés, documenter le partenaire
- **IOC (référence):** hrconnex.thm, `https://hrconnex.thm/onboarding/15400654060/j.garcia`

### 5.2 Alertes 8815 + 8816 – Phishing Amazon bloqué (True Positive, une seule chaîne)

**Timeline**

| Heure | Événement |
|---|---|
| 19:00:34 | Mail de `urgents@amazon.biz` vers `h.harris` (faux colis non livré) |
| 19:01:48 | Clic sur `http://bit.ly/3sHkX3da12340` → **blocked** (règle Blocked Websites) |

**Logique SOC :**
- Le domaine `amazon.biz`, le lien raccourci, le message générique et l'urgence (48 h) sont des signes de phishing.
- L'IP 67.199.248.11 et l'URL sont **MALICIOUS** sur TryDetectThis.
- Le firewall a bloqué la connexion avant tout impact. Aucune autre machine ni activité suspecte n'a été trouvée pour l'hôte.
- Les deux alertes forment une seule chaîne, donc la même décision s'applique à chacune : True Positive, pas d'escalade.

**Rapport**
- **Time of activity:** 08.10.2026, 19:00:34 (mail) et 19:01:48 (clic bloqué)
- **Affected entities:** Hannah Harris (RH, win-3457, 10.20.2.17)
- **Classification:** True Positive
- **Escalade:** non requise (bloqué avant impact)
- **Remédiation:** supprimer le mail, bloquer `amazon.biz`, sensibiliser l'utilisateur, surveiller l'hôte
- **IOC:** `amazon.biz`, urgents@amazon.biz, `http://bit.ly/3sHkX3da12340`, 67.199.248.11:80, 10.20.2.17

### 5.3 Alerte 8817 – Faux avertissement Microsoft (True Positive, escalade)

**Timeline**

| Heure | Événement |
|---|---|
| 19:02:52 | Mail de `no-reply@m1crosoftsupport.co` vers `c.allen` |
| 19:04:01 | Accès à `https://m1crosoftsupport.co/login` → **allowed** (45.148.10.131:443) |
| 19:05:02 | Navigation normale (Google / Asana), sans suite visible |

**Logique SOC :**
- Typosquatting (`m1crosoft`, le chiffre 1 à la place du i) et fausse alerte de connexion pour créer la peur.
- Domaine et URL **MALICIOUS** sur TryDetectThis. L'IP du texte du mail (102.89.222.143) est un leurre, pas un IOC.
- Le firewall a **autorisé** la connexion : la page de phishing a été atteinte, donc des identifiants ont pu être saisis. Le compte est à considérer comme compromis.
- Charlotte Allen a accès à `admin.thetrydaily.thm`, ce qui augmente le risque.

**Rapport**
- **Time of activity:** 08.10.2026, 19:02:52 (mail) et 19:04:01 (clic autorisé)
- **Affected entities:** Charlotte Allen (Web Development, win-3463, 10.20.2.25)
- **Classification:** True Positive
- **Escalade:** requise (connexion autorisée, compromission probable)
- **Remédiation:** reset du mot de passe, révocation des sessions, vérification MFA et des connexions récentes, blocage du domaine et de l'IP, suppression du mail, entretien avec l'utilisateur, analyse du poste
- **IOC:** `m1crosoftsupport.co`, `https://m1crosoftsupport.co/login`, 45.148.10.131:443, no-reply@m1crosoftsupport.co, 10.20.2.25
- **MITRE ATT&CK:** T1566.002 (Spearphishing Link), T1056.003 / T1078 (si les identifiants ont été saisis)

## 6. Matrice de décision

| Constat dans le firewall | Classification | Escalade |
|---|---|---|
| Aucune connexion vers l'IOC | TP | Non |
| Connexion **bloquée** | TP | Non |
| Connexion **autorisée** vers un IOC malveillant | TP | **Oui** |
| Domaine légitime confirmé en interne et TI propre | FP | Non |

## 7. Leçons apprises

- Le champ `action` (allowed / blocked) fait la différence entre « tentative » et « impact ».
- Un score TryDetectThis seul ne suffit pas ; il faut le corréler avec les logs et le contexte interne.
- Plusieurs alertes de la même chaîne doivent avoir des rapports cohérents.
- Les adresses mentionnées dans le corps d'un mail de phishing ne sont pas forcément des IOC.
- Recommandations de détection : liste blanche des partenaires tiers, détection de typosquatting, filtre sur les raccourcisseurs d'URL.

## 8. Compétences démontrées

Splunk (SPL), triage d'alertes, corrélation Email / Firewall, enrichissement threat intel, rédaction de rapports SOC, mapping MITRE ATT&CK.

---
*Lab réalisé sur TryHackMe SOC Simulator. Les noms d'entreprise, d'employés et d'IP appartiennent à l'environnement fictif.*
