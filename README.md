# ACL-Analysis-and-CSV-Export-Tool

Ce projet est un script Python qui permet d'analyser des règles d'Access Control List (ACL) et de les exporter dans un fichier CSV avec des informations détaillées, telles que les plages d'adresses IP et les ports. Le fichier peut ensuite être intégré à des outils comme Notion.

# Fonctionnalités
- Conversion des masques joker (wildcard masks) en notation CIDR
- Analyse des règles ACL à partir d'un fichier texte
- Conversion des adresses IP en plages d'adresses
- Export des règles ACL dans un fichier CSV structuré

# Les règles ACLs doivent être rentrées sous cette forme :

1 permit udp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255 eq 67
2 permit udp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255 eq 68
3 permit udp 0.0.0.0 255.255.255.255 172.23.254.111 0.0.0.0 eq 4011
