# cyber-projet1
Système de détection d'anomalies et de gestion de logs pour la sécurité des réseaux

## Configuration

Une machine virtuelle Kali (minimum 4Gb de RAM, 2 Coeurs de processeur)

## Initialisation

sudo apt update

## Installer syslog-ng sur la machine 

sudo apt install -y syslog-ng
syslog-ng --version

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
L'interface est accessible en se connectant au port ouvert (généralement 443) de l'adresse IP de la machine.  
Username : admin, et Password renseigné à la place de <ADMIN_PASSWORD>

## Installer Elasticsearch

sudo apt install -y openjdk-21-jdk

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt install -y elasticsearch

## Vérifier et créer les dossiers de données et de logs

sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
sudo chown -R elasticsearch:elasticsearch /var/log/elasticsearch
ls -ld /var/lib/elasticsearch /var/log/elasticsearch

Configuration initiale
sudo nano /etc/elasticsearch/elasticsearch.yml

Renommer sous le format suivant
cluster.name: my-cluster
node.name: node-1
network.host: 0.0.0.0
http.port: 9200

xpack.security.enabled: false

cluster.initial_master_nodes: ["node-1"]


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


Installer Kibana

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

