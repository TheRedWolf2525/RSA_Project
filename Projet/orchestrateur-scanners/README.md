# Orchestrateur de scanners de vulnérabilités

## Structure du projet

```
/orchestrateur-scanners/
|
|-- include/                      # Fichiers d'en-tête partagés par l'orchestrateur et les agents
|-- src/
|   |-- orchestrateur/            # Code de l'orchestrateur
|   |-- agent/                    # Code de l'agent
|   |-- common/                   # Implémentation du protocole et des fonctions cryptographiques
|-- tests/                        # Tests unitaires
|-- docker/                       # Environnement de test docker
|-- Makefile                      # Makefile global
```