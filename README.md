# Projet : Système de Détection d'Anomalies et de Gestion de Logs

Système de détection d'anomalies et de gestion de logs pour la sécurité des réseaux

[Configuration requise](#configuration-requise)  
[Architecture](#architecture)  
[Mise en place du système](#mise-en-place-du-système)  
[Accès au Dashboard](#accès-au-dashboard)  
[Scénarios d'attaque](#scénarios-dattaque)  

## Configuration requise

- Machine virtuelle : Kali Linux 2025.3 (version utilisée pendant les tests)
- RAM : 4096 MB minimum
- CPU : 2 cœurs
- Disque : 50 GB minimum

## Architecture

**Collecte des logs** : syslog-ng  
      |  
**Détection d'anomalies** : Wazuh Manager + agent 000 intégré  
      |  
**Gestion des logs** : Wazuh indexer - stockage et indexation  
      |  
**Visualisation des logs** : Wazuh Dashboard - accès par https://localhost  

## Mise en place du système

### Initialisation

sudo apt update

### Installer et configurer syslog-ng sur la machine

sudo apt install -y syslog-ng  
syslog-ng --version  

Configuration :  

Céer le répertoire si celui-ci n'est pas déjà existant :
sudo mkdir -p /etc/syslog-ng/conf.d

sudo nano /etc/syslog-ng/syslog-ng.conf  
Remplacer tout le contenu par :
  
    @version: 4.4
  
    options {
      chain_hostnames(off);
      flush_lines(0);
      use_dns(no);
      use_fqdn(no);
      owner("root");
      group("adm");
      perm(0640);
      stats_freq(0);
    };
    
    source s_src {
      system();
      internal();
    };
    
    destination d_wazuh {
      file("/var/log/syslog");
    };
    
    log {
      source(s_src);
      destination(d_wazuh);
    };

Exit (ctrl+X, Y, Enter)  

sudo systemctl enable syslog-ng  
sudo systemctl start syslog-ng  
sudo systemctl status syslog-ng => Le statut devrait être "active"  

Tous les logs de systemctl sont maintenant copiés dans le fichier /var/log/syslog  
  
### Installer Wazuh All-in-One

L'installation complète de Wazuh comprend wazuh-manager, wazuh-indexer et wazuh-dashboard.
Elle permet également de mettre en place automatiquement Filebeat qui s'occupe de transmettre les logs de l'agent à l'indexeur.
Le Manager comprend un agent intégré, Indexer est une alternative à Elasticsearch basé sur OpenSearch, et le Dashboard est une alternative à Kibana basée sur OpenSearch Dashboards.
Installer Wazuh permet ainsi de couvrir quatre fonctions en une étape (environ 10 minutes).

curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh
sudo chmod +x wazuh-install.sh
sudo bash ./wazuh-install.sh -a

Message d'infos à la fin de l'installation :  
"
INFO: --- Summary ---  
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>  
    User: admin  
    Password: <ADMIN_PASSWORD>  
INFO: Installation finished.  
" 

Les informations User et Password seront utiles pour se connecter au dashboard, ouvert sur le port 443 de la machine.

Il est possible de retrouver le mot de passe initial avec la commande :
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
Tous les statuts devraient être Active : Running.

Un agent Wazuh par défaut devrait être déjà lancé :
sudo /var/ossec/bin/agent_control -l

Pour éviter des problèmes de compatibilité antre agent et manager :  
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list  
apt-get update  

### Configuration de Wazuh Manager

sudo nano /var/ossec/etc/ossec.conf  
  
A la fin du fichier dans la balise <ossec_config>, supprimer tous les <localfile> et les remplacer par :  
  
    <localfile>  
      <log_format>syslog</log_format>  
      <location>/var/log/syslog</location>  
    </localfile>  
  
Puis redémarrer l'agent Wazuh :  
sudo systemctl restart wazuh-agent  

Il est possible de vérifier les alertes générées avec :
sudo tail -f /var/ossec/logs/alerts/alerts.log

## Accès au Dashboard

Le dashboard est accessible au lien : https://localhost

Un message d'alerte s'affiche avant d'accéder à la page => Advanced => Accept the risk and continue
Username et Password sont les informations renseignées plus tôt à l'installation de Wazuh.

La page d'accueil correspond à l'Overview, une synthèse des agents et des dernières alertes.

Il est possible de voir le détail des alertes et l'historique des logs en allant dans le menu (burger button en haut à gauche), puis Threat intelligence => Threat Hunting

Le dashboard réalise une synthèse du nombre d'alertes par niveau et par type d'attaques (MITRE ATTC&K).
La section Events permet de consulter toutes les alertes générées par l'agent.
Les détails comportent le temps de capture de l'événement, le nom de l'agent (ici Kali par défaut), la description de l'incident, le niveau d'alerte et l'identifiant de la règle concernée.

Il est égalemnet possible d'ajouter des filtre pour consulter plus facilement ce qui nous intéresse, notamment pour les scénarios d'attaque.

## Scénarios d'attaque

### Attaque bruteforce SSH

L’attaque par brute force ssh est l’une des menaces les plus répandues puisque la plupart des machines et serveurs sont reliés à internet. SSH est la principale méthode d'accès à distance et d'administration des serveurs Linux/Unix. Un attaquant qui réussit cette attaque obtient un accès complet au système.

#### Installation et démarrage du serveur ssh

sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh

#### Configurer wazuh-manager

sudo nano /var/ossec/etc/ossec.conf

Vérifier que la commande suivante est bien présente, sinon l'ajouter :

    <command> 
      <name>firewall-drop</name>
      <executable> firewall-drop </executable>
      <timeout_allowed>yes</timeout_allowed>
    </command>

Ajouter la règle de réponse à la fin du fichier :

    <ossec_config>
      <active-response>
        <disabled>no</disabled>
        <command>firewall-drop</command>
        <location>local</location>
        <rules_id>5763</rules_id>
        <timeout>180</timeout>
      </active-response>
    </ossec_config>

On va utiliser la commande firewall-drop définie avant, qui va être utilisé en local, avec un numéro de règle 5736, et la durée de mitigation est de 3 min.

sudo systemctl restart wazuh-manager

#### Lancer le script d'attaque avec Hydra

sudo apt install –y –hydra

Créer une liste de mots de passe et la remplir :

touch passwordlist.lst
sudo nano passwordlist.lst

list exemple de dix mots de passe erronés :

    password123
    123456
    12345678
    letmein
    canyouletmein
    password
    catsanddogs
    michael
    jackson
    azerty

Lancer la commande hydra :

sudo hydra -t 4 -l kali -P passwordlist.lst localhost ssh

Les valeurs "kali", "passwordlist.lst" et "localhost" correspondent à la présente configuration, mais il faut les adapter en fonction de ce qui a été réalisé auparavant. Le nom d'utilisateur "kali" correspond à celui par défaut sur une machine virtuelle préinstallée.

Après avoir exécuté la commande Hydra, une alerte de niveau 10 et d'id 5763 "sshd: brute force trying to get access to the system. Authentication failed." devrait apparaitre dans les logs de Wazuh.
L'attaque étant réalisée en local sur la même machine virtuelle, l'IP 127.0.0.1 ne peut pas être autobloqué. La réponse de firewall se fait donc si l'attaque vient d'une autre adresse ip.

### Attaque injection de commande

Contrairement à la force brute (qui cible l'authentification d'un service), l'injection de commandes cible directement les applications web. C'est crucial car la majorité des brèches de sécurité découlent d'une exploitation au niveau d’une faille de sécurité de l'application

#### Installer le serveur web apache et PHP

sudo apt install apache2 php libapache2-mod-php –y

#### Vérifier le statut du service

sudo systemctl status apache2

le statut doit être active (running)

#### Créer l'application web Vulnérable

##### Naviguer vers le répértoire web

cd /var/www/html/

##### Création du fichier diagnostic.php

sudo nano diagnostic.php

```php
<?php
// diagnostic.php - Application cible VULNÉRABLE à l'injection de commandes
echo "<h1>Outil de Diagnostic Réseau VULNÉRABLE (Command Injection Lab)</h1>";
if (isset($_GET['host'])) {
 $host = $_GET['host'];
 // --- POINT DE VULNÉRABILITÉ CRITIQUE ---
 // L'entrée utilisateur ($host) est insérée directement dans la commande.
 $command = 'ping -c 4 ' . $host;
 $output = shell_exec($command);
 echo "<h2>Résultat du Ping pour : " . htmlspecialchars($host) . "</h2>";
 echo "<pre>";
 if ($output === null) {
 echo "Erreur d'exécution de la commande ou aucune sortie.";
 } else {
 echo $output;
 }
 echo "</pre>";
} else {
 echo "<p>Veuillez fournir un nom d'hôte ou une adresse IP dans l'URL.</p>";
}
?>
```

Ce code est vulnérable à l'injection de commande car il manque une validation et un nettoyage appropriés de l'entrée utilisateur avant de l'exécuter dans une fonction système

#### Configuration de la surveillance des Logs Apache

L'agent doit surveiller le fichier access.log. Vérifier si dans la configuration par défaut la commande est présente, sinon l'ajouter

    <localfile> 
      <log_format>firewall-drop</log_format>
      <location> /var/log/apache2/access.log </location>
    </localfile>

redémarrer l'agent si modification du fichier 

sudo systemctl restart wazuh-agent

#### Lancement de l'attaque injection de commande

http://[IP_DE_LA_CIBLE]/diagnostic.php?host=127.0.0.1;whoami

La page web doit afficher le résultat du ping, immédiatement suivi par le nom d'utilisateur du serveur
web (souvent www-data)

On peut aussi se diriger vers events, on peut constater des logs comme :
Generic web attack: Command injection attempt
Command Injection detected in GET parameters

### Attaque modification de l'intégrité des fichiers

Cette attaque met en évidence un aspect crucial de la sécurité des serveurs : lapersistance post-exploitation et la détection comportementale.

#### definir la sequence de scan

    <syscheck> 
      <frequency>3600</frequency>
    </syscheck>

#### Ajouter les répertoires à Surveiller

la balise <directories> pour ajouter les chemins de fichiers ou de répertoires
 
    <syscheck> 
      <directories check_all= "yes">/etc/hosts</directories>
      <directories check_all= "yes"> /etc/ssh/sshd_config </directories>
    </syscheck>

l'option check_all=yes garantit que l'agent vérifie le hachage, les permissions, l'utilisateur et le groupe

sudo systemctl restart wazuh-agent

#### Lancer l'attaque File Tampering

On modifie le fichier /etc/hosts en simulant l'ajout d'une ligne par l'attaquant 

sudo echo "10.0.0.100 malicious.example.com" >> /etc/hosts

L’analyse de wazuh detecte les alertes suivantes :
Integrity checksum changed for file
File modified - higher severity
