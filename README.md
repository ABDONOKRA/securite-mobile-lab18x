# LAB 18 : FireStorm – Rapport de Démonstration
**Niveau :** Medium  
**Techniques :** Reverse Android (Jadx), Hooking Java (Frida), Authentification Firebase  
**Flag obtenu :** `PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_OR_!5_!t???}`

---

## Objectif du Challenge

L'application Android **FireStorm** contient une méthode Java (`Password()`) qui génère un mot de passe pour s'authentifier sur une base de données Firebase. Cette méthode n'est **jamais appelée** dans le flux normal de l'application. L'objectif est de :

1. Analyser l'APK statiquement avec **Jadx** pour comprendre la logique
2. Forcer l'exécution de `Password()` à l'aide de **Frida** (hooking dynamique)
3. Utiliser le mot de passe obtenu pour s'**authentifier sur Firebase**
4. Récupérer le **flag** depuis la base de données Realtime Firebase

---

## Étape 1 : Préparation de l'Environnement

### 1.1 Installation de l'APK

```bash
adb install FireStorm.apk
```

**Explication :** `adb` (Android Debug Bridge) permet de communiquer avec un émulateur ou un appareil Android connecté. La commande `install` pousse et installe l'APK sur l'appareil.

### 1.2 Vérification de Frida

```bash
frida-ps -U
```

**Explication :** `frida-ps -U` liste tous les processus en cours d'exécution sur l'appareil connecté en USB (`-U`). Si Frida server est bien lancé sur l'appareil, cette commande retourne la liste des processus.

### 1.3 Lancement de Frida Server sur l'Émulateur

```bash
# Push du binaire frida-server vers l'émulateur
adb push frida-server-17.9.1-android-x86_64 /data/local/tmp/frida-server

# Attribution des permissions d'exécution
adb shell chmod 755 /data/local/tmp/frida-server

# Lancement de frida-server en arrière-plan
adb shell /data/local/tmp/frida-server &
```

**Explication :**  
- `/data/local/tmp/` est le répertoire accessible en écriture sans root complet sur Android.  
- `chmod 755` rend le binaire exécutable.  
- Le `&` lance le processus en arrière-plan pour libérer le terminal.

> ⚠️ Il est important d'utiliser une image d'émulateur **sans Google Play Store** (`google_apis` ou `default`) car les images Play Store sont protégées et ne peuvent pas être rootées.

---

## Étape 2 : Analyse Statique avec Jadx

### 2.1 Ouverture de l'APK

```bash
jadx-gui FireStorm.apk
```

**Explication :** Jadx est un décompilateur Android qui transforme le bytecode Dalvik (`.dex`) en code Java lisible. Jadx-GUI offre une interface graphique pour naviguer dans les classes et les ressources.

### 2.2 Code de MainActivity décompilé

En naviguant vers `com.pwnsec.firestorm.MainActivity`, on trouve :

```java
package com.pwnsec.firestorm;

public class MainActivity extends AbstractActivityC0232j {

    // Chargement de la librairie native au démarrage de la classe
    static {
        System.loadLibrary("firestorm");
    }

    // Méthode qui construit le mot de passe — JAMAIS appelée dans l'app
    public String Password() {
        StringBuilder sb = new StringBuilder();

        // Récupération de chaînes stockées dans res/values/strings.xml
        String string  = getString(R.string.Friday_Night);
        String string2 = getString(R.string.Author);
        String string3 = getString(R.string.JustRandomString);
        String string4 = getString(R.string.URL);
        String string5 = getString(R.string.IDKMaybethepasswordpassowrd);
        String string6 = getString(R.string.Token);

        // Construction de la chaîne par extraction de sous-chaînes
        sb.append(string.substring(5, 9));
        sb.append(string4.substring(1, 6));
        sb.append(string2.substring(2, 6));
        sb.append(string5.substring(5, 8));
        sb.append(string3);
        sb.append(string6.substring(18, 26));

        // Appel à la fonction NATIVE pour finaliser le mot de passe
        return generateRandomString(String.valueOf(sb));
    }

    // Déclaration de la fonction native implémentée dans libfirestorm.so
    public native String generateRandomString(String str);

    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        // ... Password() n'est JAMAIS appelée ici ni ailleurs ...
        setContentView(R.layout.activity_main);
    }
}
```

### 2.3 Points clés identifiés

| Élément | Observation |
|--------|-------------|
| `Password()` | Présente dans le code mais **jamais appelée** |
| `generateRandomString()` | Fonction **native** dans `libfirestorm.so` |
| `strings.xml` | Contient les chaînes statiques + config Firebase |
| `onCreate()` | Aucun appel à `Password()` → fonction inactive |

### 2.4 Configuration Firebase dans strings.xml

```xml
<string name="firebase_api_key">AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY</string>
<string name="firebase_email">TK757567@pwnsec.xyz</string>
<string name="firebase_database_url">https://firestorm-9d3db-default-rtdb.firebaseio.com</string>
```

> Ces informations sont stockées en clair dans les ressources de l'application — une mauvaise pratique de sécurité fréquente dans les apps mobiles.

---

## Étape 3 : Hooking Dynamique avec Frida

### 3.1 Principe du Hooking Java avec Frida

Frida permet d'**injecter du code JavaScript** dans un processus Android en cours d'exécution. Il peut :
- Intercepter des appels de méthodes Java existantes (hooking)
- **Appeler manuellement** des méthodes sur des instances existantes
- Accéder aux instances Java vivantes en mémoire avec `Java.choose()`

### 3.2 Script Frida : `frida_firestorm.js`

```javascript
Java.perform(function() {

    /**
     * Fonction principale qui recherche les instances de MainActivity
     * et appelle manuellement la méthode Password()
     */
    function getPassword() {
        console.log("[*] Début de la recherche d'instances de MainActivity...");

        /**
         * Java.choose() parcourt le heap Java à la recherche de toutes
         * les instances vivantes de la classe spécifiée.
         * C'est utile quand on n'a pas de référence directe à l'objet.
         */
        Java.choose('com.pwnsec.firestorm.MainActivity', {

            /**
             * onMatch est appelé pour CHAQUE instance trouvée.
             * Le paramètre 'instance' représente l'objet Java actuel
             * (équivalent au 'this' dans le code Java de l'application).
             */
            onMatch: function(instance) {
                console.log("[+] MainActivity instance trouvée : " + instance);

                try {
                    /**
                     * Appel direct de Password() sur l'instance.
                     * Frida exécute le code Java dans le contexte réel
                     * de l'application, ce qui déclenche aussi l'appel
                     * à la fonction native generateRandomString().
                     */
                    var pass = instance.Password();

                    console.log("[+] Mot de passe Firebase généré : " + pass);

                } catch (e) {
                    console.log("[-] Erreur lors de l'appel de Password() : " + e);
                }
            },

            /**
             * onComplete est appelé une fois que Java.choose() a fini
             * de parcourir toutes les instances disponibles en mémoire.
             */
            onComplete: function() {
                console.log("[*] Recherche des instances terminée.");
            }
        });
    }

    /**
     * Java.perform() initialise l'environnement Java de Frida.
     * Tout le code interagissant avec les classes Java doit être ici.
     *
     * setTimeout() introduit un délai de 3 secondes pour :
     * - Laisser l'application démarrer complètement
     * - Attendre que MainActivity soit bien initialisée
     * - S'assurer que libfirestorm.so est chargée en mémoire
     */
    console.log("[*] Script chargé. Attente de 3 secondes avant exécution...");
    setTimeout(getPassword, 3000);
});
```

### 3.3 Lancement du Script

```bash
frida -U -n Firestorm -l frida_firestorm.js
```

**Explication des arguments :**

| Argument | Rôle |
|--------|------|
| `-U` | Connexion via USB à l'appareil/émulateur |
| `-n Firestorm` | Attache au processus nommé "Firestorm" (déjà lancé) |
| `-l frida_firestorm.js` | Charge et exécute le script JavaScript |

### 3.4 Résultat obtenu

```
[*] Script chargé. Attente de 3 secondes avant exécution...
[*] Début de la recherche d'instances de MainActivity...
[+] MainActivity instance trouvée : com.pwnsec.firestorm.MainActivity@c905a4
[+] Mot de passe Firebase généré : C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC
[*] Recherche des instances terminée.
```

> ⚠️ **Note importante :** Ce mot de passe est **dynamique** — il change à chaque lancement de l'application car la fonction native `generateRandomString()` introduit une composante aléatoire. Il faut utiliser le mot de passe immédiatement après l'avoir obtenu.

---

## Étape 4 : Authentification Firebase et Récupération du Flag

### 4.1 Installation de la dépendance

```bash
pip install pyrebase4 --break-system-packages
```

**Explication :** `pyrebase4` est une bibliothèque Python qui fournit une interface simple pour les APIs Firebase (Authentication, Realtime Database, Storage).

### 4.2 Script Python : `get_flag.py`

```python
import pyrebase

# Configuration du projet Firebase extraite de strings.xml
config = {
    "apiKey": "AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY",
    "authDomain": "firestorm-9d3db.firebaseapp.com",
    "databaseURL": "https://firestorm-9d3db-default-rtdb.firebaseio.com",
    "storageBucket": "firestorm-9d3db.appspot.com",
    "projectId": "firestorm-9d3db"
}

# Initialisation de la connexion Firebase
firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

# Credentials : email statique (strings.xml) + mot de passe dynamique (Frida)
email = "TK757567@pwnsec.xyz"
password = "C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC"  # Obtenu via Frida

# Authentification — Firebase retourne un token JWT si les credentials sont valides
user = auth.sign_in_with_email_and_password(email, password)
print("Connexion reussie. Token obtenu.")

# Connexion à la Realtime Database
# Les règles Firebase n'autorisent la lecture qu'aux utilisateurs authentifiés
db = firebase.database()

# Récupération de toutes les données à la racine avec le token d'authentification
flag_data = db.get(user['idToken'])

print("FLAG recupere :")
print(flag_data.val())
```

**Explication ligne par ligne :**

| Partie | Rôle |
|--------|------|
| `config` | Paramètres de connexion au projet Firebase (extraits de strings.xml) |
| `pyrebase.initialize_app(config)` | Initialise le SDK Firebase avec la configuration |
| `auth.sign_in_with_email_and_password()` | Appelle l'API Firebase Auth REST pour obtenir un token JWT |
| `user['idToken']` | Token JWT nécessaire pour les requêtes authentifiées à la DB |
| `db.get(user['idToken'])` | Lit toutes les données de la Realtime Database avec le token |
| `flag_data.val()` | Retourne les données sous forme de dictionnaire Python |

### 4.3 Exécution

```bash
python get_flag.py
```

### 4.4 Résultat

```
Connexion reussie. Token obtenu.
FLAG recupere :
PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_OR_!5_!t???}
```

---

## Récapitulatif des Techniques Utilisées

| Technique | Outil | But |
|-----------|-------|-----|
| Décompilation APK | **Jadx-GUI** | Lire le code Java décompilé de l'application |
| Analyse des ressources | **Jadx-GUI** | Extraire strings.xml (email, config Firebase) |
| Hooking dynamique Java | **Frida** | Appeler manuellement `Password()` sur une instance vivante |
| Appel de fonction native | **Frida** | Déclencher `generateRandomString()` via le contexte Java réel |
| Authentification Firebase | **pyrebase4** | S'authentifier avec email + mot de passe dynamique |
| Lecture Realtime Database | **pyrebase4** | Récupérer le flag protégé derrière l'authentification |

---

## Vulnérabilités Identifiées dans l'Application

1. **Secrets en clair dans les ressources** : La clé API Firebase, l'email et l'URL de la base de données sont stockés dans `strings.xml`, facilement extractibles avec Jadx.

2. **Code mort non protégé** : La méthode `Password()` existe dans le code compilé mais n'est pas appelée. Sans obfuscation ni vérification d'intégrité, elle peut être invoquée par un attaquant via Frida.

3. **Absence de Certificate Pinning / Root Detection** : L'application ne détecte pas Frida ni les environnements rootés, permettant le hooking sans obstacles.

4. **Règles Firebase insuffisantes** : La base de données est accessible en lecture à tout utilisateur authentifié, sans restriction supplémentaire sur les données sensibles.

---

## Flag Final

```
PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_OR_!5_!t???}
```
