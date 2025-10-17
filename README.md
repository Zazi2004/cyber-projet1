# cyber-projet1
Système de détection d'anomalies et de gestion de logs pour la sécurité des réseaux

## Configuration

Une machine virtuelle Kali (minimum 4Gb de RAM, 2 Coeurs de processeur)

## Initialisation

sudo apt update

## Installer et configurer syslog-ng sur la machine 

sudo apt install -y syslog-ng  
syslog-ng --version  

Configuration :  

Céer le fichier si celui-ci n'est pas déjà dans le repertoir sinon passer à l'étape suivante:
sudo mkdir -p /etc/syslog-ng/conf.d

sudo nano /etc/syslog-ng/syslog-ng.conf  
Effacer tout si du texte existe déjà, puis copier :
  
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
  
## Installer Wazuh

curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh && sudo bash ./wazuh-install.sh -a  

Message d'infos :  
"
INFO: --- Summary ---  
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>  
    User: admin  
    Password: <ADMIN_PASSWORD>  
INFO: Installation finished.  
"  
L'interface est accessible en se connectant au port ouvert (généralement 443) de de la machine => https://localhost:443/  
Un message d'alerte s'affiche avant d'accéder à la page => Advanced => Take the risk
Username : admin, et Password renseigné à la place de <ADMIN_PASSWORD>

## Déployer l'agent Wazuh

Les commandes devront être exécutées en tant que root
sudo su

Installation de la clé GPG  
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg  
  
Ajout et mise à jour du repo  
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list  
apt-get update  
  
WAZUH_MANAGER="adresse IP de la machine" apt-get install wazuh-agent  
  
Lancer le service :  
systemctl daemon-reload  
systemctl enable wazuh-agent  
systemctl start wazuh-agent  

Pour éviter des problèmes de compatibilité antre agent et manager :  
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list  
apt-get update  

sudo nano /var/ossec/etc/ossec.conf  
  
A la fin du fichier dans la dernière balise ossec_config, supprimer tous les localfile et les remplacer par :  
  
    <localfile>  
      <log_format>syslog</log_format>  
      <location>/var/log/syslog</location>  
    </localfile>  
  
Puis redémarrer l'agent Wazuh :  
sudo systemctl restart wazuh-agent  
  
## Installer Elasticsearch

sudo apt install -y openjdk-21-jdk

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
sudo apt install elasticsearch  
    
## Vérifier et créer les dossiers de données et de logs
  
sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch  
sudo chown -R elasticsearch:elasticsearch /var/log/elasticsearch  
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch  
ls -ld /var/lib/elasticsearch /var/log/elasticsearch /etc/elasticsearch    
  
Configuration initiale  
sudo nano /etc/elasticsearch/elasticsearch.yml  
  
Remplacer tout le code déjà existant par :  
  
cluster.name: syslog-ng-cluster  
node.name: node-1  
path.data: /var/lib/elasticsearch  
path.logs: /var/log/elasticsearch  
network.host: 127.0.0.1  
http.port: 9200  
discovery.type: single-node  
bootstrap.memory_lock: false  
  
Si besoin ou erreur vérifier et corriger les keystores existants  
  
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore list  
  
On remarque que certaines clés SSL sont présentes mais non utilisées car xpack.security.enabled: false.  
  
Si nécessaire, elles peuvent être supprimées après correction des permissions  
  
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch  
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore remove xpack.security.http.ssl.keystore.secure_password  
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore remove xpack.security.transport.ssl.keystore.secure_password  
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore remove xpack.security.transport.ssl.truststore.secure_password  
  
Démarrer et activer Elasticsearch  
  
sudo systemctl daemon-reexec  
sudo systemctl enable elasticsearch  
sudo systemctl start elasticsearch  
sudo systemctl status elasticsearch -l  
  
  
## Installer Kibana

sudo apt update
sudo apt install -y kibana

Configuration minimal pour kibana

sudo tee /etc/kibana/kibana.yml > /dev/null <<'YML'
server.host: "0.0.0.0"
server.port: 5601
elasticsearch.hosts: ["http://localhost:9200"]
YML


Démarrer le système 

sudo systemctl daemon-reexec
sudo systemctl enable kibana
sudo systemctl start kibana
sudo systemctl status kibana -l

## DVWA
  
https://github.com/digininja/DVWA

