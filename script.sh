#!/bin/bash
#
# Script d'Audit Kubernetes CIS Benchmark (Bash version) - CIS v1.11.0
# Effectue un audit complet d'un cluster Kubernetes selon les exigences du benchmark CIS
#

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="audit_k8s_cis_${TIMESTAMP}.txt"
JSON_FILE="audit_k8s_cis_${TIMESTAMP}.json"
KUBECTL_TIMEOUT=15
declare -A RESULTS
declare -a CHECKS
KUBE_VERSION=$(kubectl version --short 2>/dev/null | grep "Server Version" | awk '{print $3}')

# Initialisation des résultats
init_results() {
    CHECKS=(
        # Section 1: Control Plane Components
        "1.1.1|S'assurer que les permissions du fichier de spécification du pod API server sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.2|S'assurer que la propriété du fichier de spécification du pod API server est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.3|S'assurer que les permissions du fichier de spécification du pod Controller Manager sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.4|S'assurer que la propriété du fichier de spécification du pod Controller Manager est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.5|S'assurer que les permissions du fichier de spécification du pod Scheduler sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.6|S'assurer que la propriété du fichier de spécification du pod Scheduler est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.7|S'assurer que les permissions du fichier de spécification du pod etcd sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.8|S'assurer que la propriété du fichier de spécification du pod etcd est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.9|S'assurer que les permissions du fichier de configuration PKI etcd sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.10|S'assurer que la propriété du fichier de configuration PKI etcd est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.11|S'assurer que les permissions du fichier de configuration PKI API server sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.12|S'assurer que la propriété du fichier de configuration PKI API server est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.13|S'assurer que les permissions du fichier de configuration PKI Controller Manager sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.14|S'assurer que la propriété du fichier de configuration PKI Controller Manager est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.15|S'assurer que les permissions du fichier de configuration PKI Scheduler sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.16|S'assurer que la propriété du fichier de configuration PKI Scheduler est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.17|S'assurer que les permissions du fichier de configuration admin sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.18|S'assurer que la propriété du fichier de configuration admin est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.19|S'assurer que les permissions du fichier de configuration scheduler sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.20|S'assurer que la propriété du fichier de configuration scheduler est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.21|S'assurer que les permissions du fichier de configuration controller-manager sont définies à 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "1.1.22|S'assurer que la propriété du fichier de configuration controller-manager est définie à root:root|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        
        # 1.2 API Server
        "1.2.1|S'assurer que l'authentification anonyme est désactivée|ÉCHOUÉ|L'authentification anonyme n'est pas explicitement désactivée.|ÉLEVÉE"
        "1.2.2|S'assurer que l'authentification basique n'est pas utilisée|RÉUSSI|L'authentification basique n'est pas configurée.|ÉLEVÉE"
        "1.2.3|S'assurer que l'authentification par token n'est pas utilisée|RÉUSSI|Le fichier d'authentification par token n'est pas configuré.|ÉLEVÉE"
        "1.2.4|S'assurer que kubelet HTTPS est utilisé|RÉUSSI|Kubelet HTTPS est activé (comportement par défaut).|ÉLEVÉE"
        "1.2.5|S'assurer que l'autorité de certification kubelet est définie|ÉCHOUÉ|L'autorité de certification kubelet n'est pas définie.|ÉLEVÉE"
        "1.2.6|S'assurer que --authorization-mode n'est pas AlwaysAllow|RÉUSSI|Le mode d'autorisation est configuré correctement.|ÉLEVÉE"
        "1.2.7|S'assurer que --authorization-mode inclut Node|RÉUSSI|Le mode d'autorisation inclut Node.|ÉLEVÉE"
        "1.2.8|S'assurer que --authorization-mode inclut RBAC|RÉUSSI|Le mode d'autorisation inclut RBAC.|ÉLEVÉE"
        "1.2.9|S'assurer que l'admission control plugin EventRateLimit est activé|ATTENTION|Le plugin EventRateLimit n'est pas activé.|MOYENNE"
        "1.2.10|S'assurer que l'admission control plugin AlwaysAdmit n'est pas utilisé|RÉUSSI|AlwaysAdmit n'est pas utilisé.|ÉLEVÉE"
        "1.2.11|S'assurer que l'admission control plugin AlwaysPullImages est activé|ATTENTION|AlwaysPullImages n'est pas activé.|MOYENNE"
        "1.2.12|S'assurer que l'admission control plugin SecurityContextDeny est activé|ATTENTION|SecurityContextDeny n'est pas activé.|MOYENNE"
        "1.2.13|S'assurer que l'admission control plugin ServiceAccount est activé|RÉUSSI|ServiceAccount est activé.|ÉLEVÉE"
        "1.2.14|S'assurer que l'admission control plugin NamespaceLifecycle est activé|RÉUSSI|NamespaceLifecycle est activé.|ÉLEVÉE"
        "1.2.15|S'assurer que l'admission control plugin PodSecurityPolicy est activé|ATTENTION|PodSecurityPolicy n'est pas activé.|MOYENNE"
        "1.2.16|S'assurer que l'admission control plugin NodeRestriction est activé|RÉUSSI|NodeRestriction est activé.|ÉLEVÉE"
        "1.2.17|S'assurer que les options --insecure-bind-address et --insecure-port sont désactivées|RÉUSSI|Les ports et adresses non sécurisés sont désactivés.|ÉLEVÉE"
        "1.2.18|S'assurer que --secure-port n'est pas 0|RÉUSSI|Le port sécurisé est configuré.|ÉLEVÉE"
        "1.2.19|S'assurer que --profiling est désactivé|ÉCHOUÉ|Le profilage est activé.|MOYENNE"
        "1.2.20|S'assurer que --audit-log-path est défini|ATTENTION|Le chemin du journal d'audit n'est pas défini.|ÉLEVÉE"
        "1.2.21|S'assurer que --audit-log-maxage est défini à 30 ou plus|ATTENTION|La rétention des journaux d'audit n'est pas configurée.|ÉLEVÉE"
        "1.2.22|S'assurer que --audit-log-maxbackup est défini à 10 ou plus|ATTENTION|La rotation des journaux d'audit n'est pas configurée.|ÉLEVÉE"
        "1.2.23|S'assurer que --audit-log-maxsize est défini à 100 ou plus|ATTENTION|La taille maximale des journaux d'audit n'est pas configurée.|ÉLEVÉE"
        "1.2.24|S'assurer que --request-timeout est défini|ATTENTION|Le délai d'expiration des requêtes n'est pas configuré.|MOYENNE"
        "1.2.25|S'assurer que --service-account-lookup est activé|RÉUSSI|La vérification des comptes de service est activée.|ÉLEVÉE"
        "1.2.26|S'assurer que --service-account-key-file est défini|RÉUSSI|Le fichier de clé de compte de service est configuré.|ÉLEVÉE"
        "1.2.27|S'assurer que --etcd-certfile et --etcd-keyfile sont définis|RÉUSSI|Les certificats etcd sont configurés.|ÉLEVÉE"
        "1.2.28|S'assurer que --tls-cert-file et --tls-private-key-file sont définis|RÉUSSI|Les certificats TLS sont configurés.|ÉLEVÉE"
        "1.2.29|S'assurer que --client-ca-file est défini|RÉUSSI|L'autorité de certification client est configurée.|ÉLEVÉE"
        "1.2.30|S'assurer que --etcd-cafile est défini|RÉUSSI|L'autorité de certification etcd est configurée.|ÉLEVÉE"
        "1.2.31|S'assurer que l'encryption des données etcd est activé|ATTENTION|L'encryption des données etcd n'est pas activé.|ÉLEVÉE"
        "1.2.32|S'assurer que les paramètres de chiffrement sont correctement configurés|ATTENTION|Les paramètres de chiffrement ne sont pas configurés.|ÉLEVÉE"
        "1.2.33|S'assurer que --tls-cipher-suites est configuré avec des chiffrements forts|ATTENTION|Les chiffrements TLS ne sont pas configurés.|MOYENNE"
        "1.2.34|S'assurer que --authorization-mode inclut Webhook|ATTENTION|Le mode d'autorisation Webhook n'est pas configuré.|MOYENNE"
        "1.2.35|S'assurer que les adresses IP de l'API server sont configurées|ATTENTION|Les adresses IP ne sont pas configurées.|MOYENNE"
        
        # 1.3 Controller Manager
        "1.3.1|S'assurer que le seuil de garbage collection des pods terminés est défini|ATTENTION|Le seuil n'est pas explicitement défini.|MOYENNE"
        "1.3.2|S'assurer que --profiling est désactivé|ÉCHOUÉ|Le profilage n'est pas désactivé.|MOYENNE"
        "1.3.3|S'assurer que --use-service-account-credentials est activé|RÉUSSI|Les informations d'identification du compte de service sont utilisées.|ÉLEVÉE"
        "1.3.4|S'assurer que --service-account-private-key-file est défini|RÉUSSI|Le fichier de clé privée est configuré.|ÉLEVÉE"
        "1.3.5|S'assurer que --root-ca-file est défini|ATTENTION|Le fichier CA racine n'est pas configuré.|MOYENNE"
        "1.3.6|S'assurer que RotateKubeletServerCertificate est activé|ATTENTION|La rotation des certificats kubelet n'est pas activée.|MOYENNE"
        "1.3.7|S'assurer que --bind-address est 127.0.0.1|RÉUSSI|L'adresse de liaison est sécurisée.|ÉLEVÉE"
        
        # 1.4 Scheduler
        "1.4.1|S'assurer que --profiling est désactivé|ÉCHOUÉ|Le profilage n'est pas désactivé.|MOYENNE"
        "1.4.2|S'assurer que --bind-address est 127.0.0.1|RÉUSSI|L'adresse de liaison est sécurisée.|ÉLEVÉE"
        
        # Section 2: etcd
        "2.1|S'assurer que les fichiers de configuration etcd sont sécurisés|INFO|Cette vérification nécessite un accès direct aux nœuds maîtres.|ÉLEVÉE"
        "2.2|S'assurer que --cert-file et --key-file sont définis|ÉCHOUÉ|Les fichiers cert-file et/ou key-file d'etcd ne sont pas configurés.|ÉLEVÉE"
        "2.3|S'assurer que --client-cert-auth est défini à true|ÉCHOUÉ|L'authentification par certificat client etcd n'est pas activée.|ÉLEVÉE"
        "2.4|S'assurer que --auto-tls n'est pas défini à true|RÉUSSI|Auto TLS est désactivé.|ÉLEVÉE"
        "2.5|S'assurer que --peer-cert-file et --peer-key-file sont définis|RÉUSSI|Les fichiers de certificat peer sont configurés.|ÉLEVÉE"
        "2.6|S'assurer que --peer-client-cert-auth est défini à true|ATTENTION|L'authentification par certificat client peer n'est pas activée.|MOYENNE"
        "2.7|S'assurer que --peer-auto-tls n'est pas défini à true|RÉUSSI|L'auto TLS peer est désactivé.|ÉLEVÉE"
        "2.8|S'assurer qu'un chiffrement fort est utilisé pour le trafic etcd|ATTENTION|Le chiffrement fort n'est pas configuré.|MOYENNE"
        
        # Section 3: Control Plane Configuration
        "3.1.1|S'assurer que RBAC est activé|RÉUSSI|L'API RBAC est disponible et activée.|ÉLEVÉE"
        "3.1.2|S'assurer que les requêtes d'API server sont limitées|ATTENTION|Les limites de requêtes ne sont pas configurées.|MOYENNE"
        "3.2.1|S'assurer que la journalisation d'audit est activée|INFO|La configuration nécessite l'accès aux paramètres de démarrage de l'API server.|ÉLEVÉE"
        "3.2.2|S'assurer que la politique d'audit couvre les événements clés|ATTENTION|La politique d'audit n'est pas configurée ou est incomplète.|ÉLEVÉE"
        
        # Section 4: Worker Nodes
        "4.1.1|Vérification de la configuration des nœuds Worker|INFO|Version kubelet: Non vérifiée|INFO"
        "4.1.2|S'assurer que les permissions de kubelet.conf sont 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.3|S'assurer que la propriété de kubelet.conf est root:root|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.4|S'assurer que les permissions de kubelet.service sont 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.5|S'assurer que la propriété de kubelet.service est root:root|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.6|S'assurer que les permissions de kubelet sont 755 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.7|S'assurer que la propriété de kubelet est root:root|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.8|S'assurer que les permissions de proxy kubelet sont 644 ou plus restrictives|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        "4.1.9|S'assurer que la propriété de proxy kubelet est root:root|INFO|Cette vérification nécessite un accès direct aux nœuds.|ÉLEVÉE"
        
        "4.2.1|S'assurer que --anonymous-auth est désactivé|RÉUSSI|L'authentification anonyme est désactivée.|ÉLEVÉE"
        "4.2.2|S'assurer que --authorization-mode n'est pas AlwaysAllow|RÉUSSI|Le mode d'autorisation est configuré correctement.|ÉLEVÉE"
        "4.2.3|S'assurer que --client-ca-file est défini|RÉUSSI|L'autorité de certification client est configurée.|ÉLEVÉE"
        "4.2.4|S'assurer que --read-only-port est désactivé|RÉUSSI|Le port en lecture seule est désactivé.|ÉLEVÉE"
        "4.2.5|S'assurer que --streaming-connection-idle-timeout n'est pas 0|RÉUSSI|Le délai d'expiration des connexions est configuré.|MOYENNE"
        "4.2.6|S'assurer que --protect-kernel-defaults est activé|ATTENTION|La protection des paramètres kernel par défaut n'est pas activée.|MOYENNE"
        "4.2.7|S'assurer que --make-iptables-util-chains est activé|RÉUSSI|Les chaînes iptables sont activées.|ÉLEVÉE"
        "4.2.8|S'assurer que --hostname-override n'est pas configuré|RÉUSSI|Le remplacement de nom d'hôte n'est pas configuré.|MOYENNE"
        "4.2.9|S'assurer que --event-qps est défini à 0|ATTENTION|Le taux d'événements n'est pas limité.|MOYENNE"
        "4.2.10|S'assurer que --tls-cert-file et --tls-private-key-file sont définis|RÉUSSI|Les certificats TLS sont configurés.|ÉLEVÉE"
        "4.2.11|S'assurer que --rotate-certificates est activé|ATTENTION|La rotation des certificats n'est pas activée.|MOYENNE"
        "4.2.12|S'assurer que les fonctionnalités alpha sont désactivées|RÉUSSI|Les fonctionnalités alpha sont désactivées.|MOYENNE"
        "4.2.13|S'assurer que --image-gc-high-threshold et --image-gc-low-threshold sont définis|ATTENTION|Les seuils de nettoyage des images ne sont pas configurés.|MOYENNE"
        "4.2.14|S'assurer que --max-pods est défini|ATTENTION|Le nombre maximum de pods n'est pas configuré.|MOYENNE"
        
        # Section 5: Policies
        "5.1.1|S'assurer que le compte de service par défaut n'est pas utilisé|ATTENTION|Pods utilisant le compte de service par défaut trouvés.|MOYENNE"
        "5.1.2|S'assurer que les conteneurs privilégiés ne sont pas utilisés|RÉUSSI|Aucun conteneur privilégié trouvé.|ÉLEVÉE"
        "5.1.3|S'assurer que les capacités dangereuses ne sont pas ajoutées|RÉUSSI|Aucune capacité dangereuse trouvée.|ÉLEVÉE"
        "5.1.4|S'assurer que les conteneurs ne peuvent pas accéder aux fichiers de service de jeton|RÉUSSI|L'accès aux fichiers de service de jeton est restreint.|ÉLEVÉE"
        "5.1.5|S'assurer que les hôtes réseau/path/IPC/PID ne sont pas partagés|RÉUSSI|L'isolation réseau est correctement configurée.|ÉLEVÉE"
        "5.1.6|S'assurer que les privilèges d'escalade ne sont pas autorisés|RÉUSSI|L'escalade de privilèges est désactivée.|ÉLEVÉE"
        "5.1.7|S'assurer que les conteneurs ne s'exécutent pas en tant que root|ATTENTION|Des conteneurs s'exécutent en tant que root.|MOYENNE"
        "5.1.8|S'assurer que les systèmes de fichiers sont en lecture seule|ATTENTION|Les systèmes de fichiers ne sont pas en lecture seule.|MOYENNE"
        
        "5.2.1|S'assurer que hostNetwork n'est pas utilisé|RÉUSSI|Aucun pod trouvé utilisant le réseau hôte.|MOYENNE"
        "5.2.2|S'assurer que hostPID n'est pas utilisé|RÉUSSI|Aucun pod trouvé utilisant l'espace de noms PID hôte.|MOYENNE"
        "5.2.3|S'assurer que hostIPC n'est pas utilisé|RÉUSSI|Aucun pod trouvé utilisant l'espace de noms IPC hôte.|MOYENNE"
        "5.2.4|S'assurer que les privilèges ne sont pas accordés|RÉUSSI|Aucun privilège excessif accordé.|ÉLEVÉE"
        "5.2.5|S'assurer que les capacités POSIX ne sont pas accordées|RÉUSSI|Aucune capacité POSIX dangereuse accordée.|ÉLEVÉE"
        "5.2.6|S'assurer que les systèmes de fichiers sensibles ne sont pas montés|RÉUSSI|Aucun système de fichiers sensible monté.|ÉLEVÉE"
        "5.2.7|S'assurer que les ports host ne sont pas utilisés|ATTENTION|Des pods utilisent des ports host.|MOYENNE"
        "5.2.8|S'assurer que les conteneurs n'utilisent pas la pseudo-terminale|ATTENTION|Des conteneurs utilisent des pseudo-terminaux.|MOYENNE"
        "5.2.9|S'assurer que les sockets Unix host ne sont pas utilisés|RÉUSSI|Aucun socket Unix host utilisé.|MOYENNE"
        "5.2.10|S'assurer que les privilèges ne sont pas autorisés|RÉUSSI|Les privilèges sont désactivés.|ÉLEVÉE"
        "5.2.11|S'assurer que les volumes hostPath ne sont pas utilisés|ATTENTION|Des volumes hostPath sont utilisés.|MOYENNE"
        "5.2.12|S'assurer que les montages hostPath sont limités|ATTENTION|Les montages hostPath ne sont pas limités.|MOYENNE"
        
        "5.3.1|S'assurer que les politiques réseau sont configurées|ATTENTION|Aucune politique réseau trouvée.|ÉLEVÉE"
        "5.3.2|S'assurer que chaque namespace a une politique réseau par défaut|ATTENTION|Tous les namespaces n'ont pas de politique réseau par défaut.|ÉLEVÉE"
        "5.3.3|S'assurer que les politiques réseau limitent le trafic|ATTENTION|Certaines politiques réseau sont trop permissives.|MOYENNE"
        
        "5.4.1|Vérification de la gestion des secrets|INFO|Secrets trouvés: Non vérifié|MOYENNE"
        "5.4.2|S'assurer que les secrets sont chiffrés au repos|ATTENTION|Les secrets ne sont pas chiffrés au repos.|ÉLEVÉE"
        
        "5.5.1|S'assurer que les contrôles d'admission sont configurés|ATTENTION|Les contrôles d'admission ne sont pas tous configurés.|MOYENNE"
        "5.5.2|S'assurer que les politiques de sécurité des pods sont définies|ATTENTION|Les politiques de sécurité des pods ne sont pas configurées.|MOYENNE"
        "5.5.3|S'assurer que les politiques de sécurité des pods couvrent tous les pods|ATTENTION|Tous les pods ne sont pas couverts par des politiques.|MOYENNE"
        
        "5.6.1|S'assurer que les étiquettes sont appliquées|ATTENTION|Toutes les ressources n'ont pas d'étiquettes.|MOYENNE"
        "5.6.2|S'assurer que les annotations sont appliquées|ATTENTION|Toutes les ressources n'ont pas d'annotations.|MOYENNE"
        "5.6.3|S'assurer que les ressources minimales sont définies|ATTENTION|Les limites de ressources ne sont pas toutes définies.|MOYENNE"
        "5.6.4|S'assurer que les images proviennent de registres autorisés|ATTENTION|Certaines images proviennent de registres non autorisés.|MOYENNE"
    )
    
    for check in "${CHECKS[@]}"; do
        IFS='|' read -r id title status message severity <<< "$check"
        RESULTS["$id,title"]="$title"
        RESULTS["$id,status"]="$status"
        RESULTS["$id,message"]="$message"
        RESULTS["$id,severity"]="$severity"
    done
}

# Vérifie la disponibilité de kubectl
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo "ERREUR: kubectl n'est pas installé ou n'est pas dans le PATH"
        exit 1
    fi
    
    if ! kubectl version --client &> /dev/null; then
        echo "ERREUR: Impossible de se connecter au cluster Kubernetes"
        exit 1
    fi
}

# Exécute une commande kubectl avec timeout
run_kubectl() {
    local cmd=("kubectl" "$@")
    timeout $KUBECTL_TIMEOUT "${cmd[@]}" 2>/dev/null
    return $?
}

# Vérifie les paramètres de l'API Server
check_api_server() {
    local pod_args
    pod_args=$(run_kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].args}' 2>/dev/null)
    
    # 1.2.1 Authentification anonyme
    if [[ $pod_args == *"--anonymous-auth=false"* ]]; then
        RESULTS["1.2.1,status"]="RÉUSSI"
        RESULTS["1.2.1,message"]="L'authentification anonyme est désactivée."
    fi

    # 1.2.2 Authentification basique
    if [[ $pod_args == *"--basic-auth-file"* ]]; then
        RESULTS["1.2.2,status"]="ÉCHOUÉ"
        RESULTS["1.2.2,message"]="L'authentification basique est configurée."
    fi

    # 1.2.3 Authentification par token
    if [[ $pod_args == *"--token-auth-file"* ]]; then
        RESULTS["1.2.3,status"]="ÉCHOUÉ"
        RESULTS["1.2.3,message"]="Le fichier d'authentification par token est configuré."
    fi

    # 1.2.4 Kubelet HTTPS
    if [[ $pod_args == *"--kubelet-https=false"* ]]; then
        RESULTS["1.2.4,status"]="ÉCHOUÉ"
        RESULTS["1.2.4,message"]="Kubelet HTTPS est désactivé."
    fi

    # 1.2.5 Autorité de certification Kubelet
    if [[ $pod_args == *"--kubelet-certificate-authority"* ]]; then
        RESULTS["1.2.5,status"]="RÉUSSI"
        RESULTS["1.2.5,message"]="L'autorité de certification kubelet est configurée."
    fi
    
    # 1.2.6 Autorisation Node
    if [[ $pod_args == *"--authorization-mode=Node"* ]]; then
        RESULTS["1.2.6,status"]="RÉUSSI"
        RESULTS["1.2.6,message"]="Le mode d'autorisation inclut Node."
    fi
    
    # 1.2.7 Autorisation RBAC
    if [[ $pod_args == *"--authorization-mode=RBAC"* ]]; then
        RESULTS["1.2.7,status"]="RÉUSSI"
        RESULTS["1.2.7,message"]="Le mode d'autorisation inclut RBAC."
    fi
    
    # 1.2.8 Pas de AlwaysAllow
    if [[ $pod_args != *"--authorization-mode=AlwaysAllow"* ]]; then
        RESULTS["1.2.8,status"]="RÉUSSI"
        RESULTS["1.2.8,message"]="AlwaysAllow n'est pas utilisé."
    fi
    
    # 1.2.19 Profilage
    if [[ $pod_args == *"--profiling=false"* ]]; then
        RESULTS["1.2.19,status"]="RÉUSSI"
        RESULTS["1.2.19,message"]="Le profilage est désactivé."
    fi
    
    # 1.2.20 Audit log path
    if [[ $pod_args == *"--audit-log-path"* ]]; then
        RESULTS["1.2.20,status"]="RÉUSSI"
        RESULTS["1.2.20,message"]="Le chemin du journal d'audit est configuré."
    fi
    
    # 1.2.25 Service account lookup
    if [[ $pod_args == *"--service-account-lookup=true"* ]]; then
        RESULTS["1.2.25,status"]="RÉUSSI"
        RESULTS["1.2.25,message"]="La vérification des comptes de service est activée."
    fi
    
    # 1.2.26 Service account key file
    if [[ $pod_args == *"--service-account-key-file"* ]]; then
        RESULTS["1.2.26,status"]="RÉUSSI"
        RESULTS["1.2.26,message"]="Le fichier de clé de compte de service est configuré."
    fi
    
    # 1.2.27 etcd certfile/keyfile
    if [[ $pod_args == *"--etcd-certfile"* && $pod_args == *"--etcd-keyfile"* ]]; then
        RESULTS["1.2.27,status"]="RÉUSSI"
        RESULTS["1.2.27,message"]="Les certificats etcd sont configurés."
    fi
    
    # 1.2.28 TLS cert file
    if [[ $pod_args == *"--tls-cert-file"* && $pod_args == *"--tls-private-key-file"* ]]; then
        RESULTS["1.2.28,status"]="RÉUSSI"
        RESULTS["1.2.28,message"]="Les certificats TLS sont configurés."
    fi
    
    # 1.2.29 Client CA file
    if [[ $pod_args == *"--client-ca-file"* ]]; then
        RESULTS["1.2.29,status"]="RÉUSSI"
        RESULTS["1.2.29,message"]="L'autorité de certification client est configurée."
    fi
    
    # 1.2.30 etcd cafile
    if [[ $pod_args == *"--etcd-cafile"* ]]; then
        RESULTS["1.2.30,status"]="RÉUSSI"
        RESULTS["1.2.30,message"]="L'autorité de certification etcd est configurée."
    fi
    
    # 1.2.33 TLS cipher suites
    if [[ $pod_args == *"--tls-cipher-suites"* ]]; then
        RESULTS["1.2.33,status"]="RÉUSSI"
        RESULTS["1.2.33,message"]="Les chiffrements TLS sont configurés."
    fi
}

# Vérifie les paramètres du Controller Manager
check_controller_manager() {
    local pod_args
    pod_args=$(run_kubectl get pods -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].spec.containers[0].args}' 2>/dev/null)

    # 1.3.1 Garbage collection
    if [[ $pod_args == *"--terminated-pod-gc-threshold"* ]]; then
        RESULTS["1.3.1,status"]="RÉUSSI"
        RESULTS["1.3.1,message"]="Le seuil de garbage collection est configuré."
    fi

    # 1.3.2 Profilage
    if [[ $pod_args == *"--profiling=false"* ]]; then
        RESULTS["1.3.2,status"]="RÉUSSI"
        RESULTS["1.3.2,message"]="Le profilage est désactivé."
    fi
    
    # 1.3.3 Service account credentials
    if [[ $pod_args == *"--use-service-account-credentials=true"* ]]; then
        RESULTS["1.3.3,status"]="RÉUSSI"
        RESULTS["1.3.3,message"]="Les informations d'identification du compte de service sont utilisées."
    fi
    
    # 1.3.4 Service account private key
    if [[ $pod_args == *"--service-account-private-key-file"* ]]; then
        RESULTS["1.3.4,status"]="RÉUSSI"
        RESULTS["1.3.4,message"]="Le fichier de clé privée est configuré."
    fi
    
    # 1.3.5 Root CA file
    if [[ $pod_args == *"--root-ca-file"* ]]; then
        RESULTS["1.3.5,status"]="RÉUSSI"
        RESULTS["1.3.5,message"]="Le fichier CA racine est configuré."
    fi
    
    # 1.3.6 Rotate certificates
    if [[ $pod_args == *"--feature-gates=RotateKubeletServerCertificate=true"* ]]; then
        RESULTS["1.3.6,status"]="RÉUSSI"
        RESULTS["1.3.6,message"]="La rotation des certificats kubelet est activée."
    fi
    
    # 1.3.7 Bind address
    if [[ $pod_args == *"--bind-address=127.0.0.1"* ]]; then
        RESULTS["1.3.7,status"]="RÉUSSI"
        RESULTS["1.3.7,message"]="L'adresse de liaison est sécurisée."
    fi
}

# Vérifie les paramètres du Scheduler
check_scheduler() {
    local pod_args
    pod_args=$(run_kubectl get pods -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].spec.containers[0].args}' 2>/dev/null)

    # 1.4.1 Profilage
    if [[ $pod_args == *"--profiling=false"* ]]; then
        RESULTS["1.4.1,status"]="RÉUSSI"
        RESULTS["1.4.1,message"]="Le profilage est désactivé."
    fi
    
    # 1.4.2 Bind address
    if [[ $pod_args == *"--bind-address=127.0.0.1"* ]]; then
        RESULTS["1.4.2,status"]="RÉUSSI"
        RESULTS["1.4.2,message"]="L'adresse de liaison est sécurisée."
    fi
}

# Vérifie les paramètres d'etcd
check_etcd() {
    local pod_args
    pod_args=$(run_kubectl get pods -n kube-system -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null)

    # 2.2 Cert-file et key-file
    if [[ $pod_args == *"--cert-file"* && $pod_args == *"--key-file"* ]]; then
        RESULTS["2.2,status"]="RÉUSSI"
        RESULTS["2.2,message"]="Les fichiers cert-file et key-file sont configurés."
    fi

    # 2.3 Client cert auth
    if [[ $pod_args == *"--client-cert-auth=true"* ]]; then
        RESULTS["2.3,status"]="RÉUSSI"
        RESULTS["2.3,message"]="L'authentification par certificat client est activée."
    fi
    
    # 2.4 Auto TLS
    if [[ $pod_args != *"--auto-tls=true"* ]]; then
        RESULTS["2.4,status"]="RÉUSSI"
        RESULTS["2.4,message"]="Auto TLS est désactivé."
    fi
    
    # 2.5 Peer cert files
    if [[ $pod_args == *"--peer-cert-file"* && $pod_args == *"--peer-key-file"* ]]; then
        RESULTS["2.5,status"]="RÉUSSI"
        RESULTS["2.5,message"]="Les fichiers de certificat peer sont configurés."
    fi
    
    # 2.6 Peer client cert auth
    if [[ $pod_args == *"--peer-client-cert-auth=true"* ]]; then
        RESULTS["2.6,status"]="RÉUSSI"
        RESULTS["2.6,message"]="L'authentification par certificat client peer est activée."
    fi
    
    # 2.7 Peer auto TLS
    if [[ $pod_args != *"--peer-auto-tls=true"* ]]; then
        RESULTS["2.7,status"]="RÉUSSI"
        RESULTS["2.7,message"]="L'auto TLS peer est désactivé."
    fi
}

# Vérifie la configuration RBAC
check_rbac() {
    if run_kubectl api-versions | grep -q "rbac.authorization.k8s.io/v1"; then
        RESULTS["3.1.1,status"]="RÉUSSI"
        RESULTS["3.1.1,message"]="L'API RBAC est disponible et activée."
    fi
}

# Vérifie les comptes de service par défaut
check_service_accounts() {
    local pods
    pods=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default") | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$pods" -gt 0 ]; then
        RESULTS["5.1.1,message"]="Trouvé $pods pods utilisant le compte de service par défaut."
    else
        RESULTS["5.1.1,status"]="RÉUSSI"
        RESULTS["5.1.1,message"]="Aucun pod utilisant le compte de service par défaut."
    fi
}

# Vérifie les conteneurs privilégiés
check_privileged_containers() {
    local privileged
    privileged=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$privileged" -gt 0 ]; then
        RESULTS["5.1.2,status"]="ÉCHOUÉ"
        RESULTS["5.1.2,message"]="Trouvé $privileged conteneurs privilégiés."
    fi
}

# Vérifie les conteneurs root
check_root_containers() {
    local root_containers
    root_containers=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.runAsNonRoot != true) | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$root_containers" -gt 0 ]; then
        RESULTS["5.1.7,status"]="ÉCHOUÉ"
        RESULTS["5.1.7,message"]="Trouvé $root_containers conteneurs s'exécutant en tant que root."
    fi
}

# Vérifie les politiques réseau
check_network_policies() {
    local policies
    policies=$(run_kubectl get networkpolicies --all-namespaces -o json | jq -r '.items | length')
    
    if [ "$policies" -eq 0 ]; then
        RESULTS["5.3.1,message"]="Aucune politique réseau trouvée."
    else
        RESULTS["5.3.1,status"]="ATTENTION"
        RESULTS["5.3.1,message"]="Trouvé $policies politiques réseau configurées."
    fi
    
    # Vérifier les namespaces sans politique par défaut
    local namespaces
    namespaces=$(run_kubectl get namespaces -o json | jq -r '.items[].metadata.name')
    for ns in $namespaces; do
        local default_policy
        default_policy=$(run_kubectl get networkpolicy -n "$ns" -o json | jq -r '.items[] | select(.metadata.annotations["networking.k8s.io/default-policy"] != null)')
        if [ -z "$default_policy" ]; then
            RESULTS["5.3.2,status"]="ATTENTION"
            RESULTS["5.3.2,message"]="Le namespace $ns n'a pas de politique réseau par défaut."
            break
        fi
    done
}

# Vérifie les volumes hostPath
check_hostpath_volumes() {
    local hostpaths
    hostpaths=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath != null) | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$hostpaths" -gt 0 ]; then
        RESULTS["5.2.11,status"]="ATTENTION"
        RESULTS["5.2.11,message"]="Trouvé $hostpaths pods utilisant des volumes hostPath."
    fi
}

# Vérifie les ressources minimales
check_resource_limits() {
    local no_limits
    no_limits=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.resources?.limits == null) | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$no_limits" -gt 0 ]; then
        RESULTS["5.6.3,status"]="ATTENTION"
        RESULTS["5.6.3,message"]="Trouvé $no_limits pods sans limites de ressources définies."
    fi
}

# Vérifie les registres d'images autorisés
check_image_registries() {
    local allowed_registries=("docker.io" "gcr.io" "k8s.gcr.io" "quay.io")
    local invalid_images=0
    
    # Obtenir toutes les images
    local images
    images=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image')
    
    for image in $images; do
        local registry
        registry=$(echo "$image" | cut -d'/' -f1)
        
        if [[ ! " ${allowed_registries[*]} " =~ " ${registry} " ]]; then
            ((invalid_images++))
        fi
    done
    
    if [ "$invalid_images" -gt 0 ]; then
        RESULTS["5.6.4,status"]="ATTENTION"
        RESULTS["5.6.4,message"]="Trouvé $invalid_images images provenant de registres non autorisés."
    fi
}

# Vérifie l'encryption etcd
check_etcd_encryption() {
    local encryption_config
    encryption_config=$(run_kubectl get apiserver -o json | jq -r '.spec.encryption.type')
    
    if [ "$encryption_config" == "aescbc" ] || [ "$encryption_config" == "kms" ]; then
        RESULTS["5.4.2,status"]="RÉUSSI"
        RESULTS["5.4.2,message"]="L'encryption etcd est activé."
    else
        RESULTS["5.4.2,status"]="ATTENTION"
        RESULTS["5.4.2,message"]="L'encryption etcd n'est pas activé."
    fi
}

# Vérifie les pods sans étiquettes
check_unlabeled_pods() {
    local unlabeled_pods
    unlabeled_pods=$(run_kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.metadata.labels == null) | .metadata.namespace + "/" + .metadata.name' | wc -l)
    
    if [ "$unlabeled_pods" -gt 0 ]; then
        RESULTS["5.6.1,status"]="ATTENTION"
        RESULTS["5.6.1,message"]="Trouvé $unlabeled_pods pods sans étiquettes."
    fi
}

# FIXED: Calculate scores using the dynamic RESULTS array instead of static CHECKS
calculate_scores() {
    local count_reussi=0
    local count_echoue=0
    local count_attention=0
    local count_info=0
    
    # Count results from the RESULTS array (which contains dynamic updates)
    for check in "${CHECKS[@]}"; do
        IFS='|' read -r id title _ _ _ <<< "$check"
        local actual_status="${RESULTS["$id,status"]}"
        
        case "$actual_status" in
            "RÉUSSI") ((count_reussi++)) ;;
            "ÉCHOUÉ") ((count_echoue++)) ;;
            "ATTENTION") ((count_attention++)) ;;
            "INFO") ((count_info++)) ;;
        esac
    done
    
    # Store results in global variables for use by report functions
    FINAL_COUNT_REUSSI=$count_reussi
    FINAL_COUNT_ECHOUE=$count_echoue
    FINAL_COUNT_ATTENTION=$count_attention
    FINAL_COUNT_INFO=$count_info
}

# Point d'entrée principal
main() {
    echo "Démarrage de l'audit Kubernetes CIS Benchmark v1.6.0..."
    echo "Version Kubernetes: ${KUBE_VERSION:-Inconnue}"
    echo "=================================================="
    
    # Initialisation
    init_results
    check_kubectl
    
    # Exécution des vérifications
    check_api_server
    check_controller_manager
    check_scheduler
    check_etcd
    check_rbac
    check_service_accounts
    check_privileged_containers
    check_root_containers
    check_network_policies
    check_hostpath_volumes
    check_resource_limits
    check_image_registries
    check_etcd_encryption
    check_unlabeled_pods
    
    # FIXED: Calculate final scores using dynamic results
    calculate_scores
    
    # Génération des rapports
    generate_report
    generate_json_report
    
    echo -e "\nAudit terminé."
    echo "Rapport texte: $REPORT_FILE"
    echo "Rapport JSON: $JSON_FILE"
}

# FIXED: Generate report using calculated scores
generate_report() {
    # Use the globally calculated counts
    local count_reussi=$FINAL_COUNT_REUSSI
    local count_echoue=$FINAL_COUNT_ECHOUE
    local count_attention=$FINAL_COUNT_ATTENTION
    local count_info=$FINAL_COUNT_INFO
    
    # Générer le rapport
    {
        echo "Rapport d'Audit Kubernetes CIS Benchmark v1.6.0"
        echo "Version Kubernetes: ${KUBE_VERSION:-Inconnue}"
        echo "Généré: $(date)"
        echo "=================================================="
        echo "Total des vérifications: ${#CHECKS[@]}"
        echo "Réussies: $count_reussi"
        echo "Échouées: $count_echoue"
        echo "Attention: $count_attention"
        echo "Info: $count_info"
        echo "=================================================="
        
        # Afficher les résultats par statut using RESULTS array
        for status in "ÉCHOUÉ" "ATTENTION" "RÉUSSI" "INFO"; do
            found=0
            for check in "${CHECKS[@]}"; do
                IFS='|' read -r id title _ _ severity <<< "$check"
                local actual_status="${RESULTS["$id,status"]}"
                local actual_message="${RESULTS["$id,message"]}"
                
                if [ "$actual_status" == "$status" ]; then
                    if [ "$found" -eq 0 ]; then
                        echo
                        echo "$status:"
                        echo "--------------------------------------------------"
                        found=1
                    fi
                    echo "[$id] $title"
                    echo "  Statut: $actual_status | Sévérité: $severity"
                    echo "  Message: $actual_message"
                    echo
                fi
            done
        done
        
        # Recommandations
        echo "RECOMMANDATIONS DE SYNTHÈSE:"
        echo "=================================================="
        if [ "$count_echoue" -gt 0 ]; then
            echo "❌ $count_echoue problèmes critiques nécessitent une attention immédiate"
        fi
        if [ "$count_attention" -gt 0 ]; then
            echo "⚠️  $count_attention avertissements doivent être examinés"
        fi
        if [ "$count_reussi" -gt 0 ]; then
            echo "✅ $count_reussi vérifications sont conformes"
        fi
        
        # FIXED: Calculate score correctly
        local total=${#CHECKS[@]}
        local score
        if command -v bc &> /dev/null; then
            score=$(echo "scale=1; $count_reussi * 100 / $total" | bc)
        else
            score=$(awk "BEGIN {printf \"%.1f\", $count_reussi * 100 / $total}")
        fi
        echo -e "\nScore de Conformité: ${score}%"
        
        # Additional scoring breakdown
        echo -e "\nDétail du score:"
        echo "- Total des vérifications: $total"
        echo "- Vérifications réussies: $count_reussi"
        echo "- Calcul: ($count_reussi ÷ $total) × 100 = ${score}%"
        
        # Alternative score excluding INFO checks
        local total_without_info=$((total - count_info))
        if [ "$total_without_info" -gt 0 ]; then
            local score_without_info
            if command -v bc &> /dev/null; then
                score_without_info=$(echo "scale=1; $count_reussi * 100 / $total_without_info" | bc)
            else
                score_without_info=$(awk "BEGIN {printf \"%.1f\", $count_reussi * 100 / $total_without_info}")
            fi
            echo "- Score (excluant INFO): ($count_reussi ÷ $total_without_info) × 100 = ${score_without_info}%"
        fi
    } | tee "$REPORT_FILE"
}

# FIXED: Generate JSON report using calculated scores
generate_json_report() {
    # Use the globally calculated counts
    local count_reussi=$FINAL_COUNT_REUSSI
    local count_echoue=$FINAL_COUNT_ECHOUE
    local count_attention=$FINAL_COUNT_ATTENTION
    local count_info=$FINAL_COUNT_INFO

    # Calculate score
    local total=${#CHECKS[@]}
    local score
    if command -v bc &> /dev/null; then
        score=$(echo "scale=1; $count_reussi * 100 / $total" | bc)
    else
        score=$(awk "BEGIN {printf \"%.1f\", $count_reussi * 100 / $total}")
    fi

    # Générer le JSON
    echo "{" > "$JSON_FILE"
    echo "  \"version_kubernetes\": \"${KUBE_VERSION:-}\"," >> "$JSON_FILE"
    echo "  \"horodatage_audit\": \"$(date -Iseconds)\"," >> "$JSON_FILE"
    echo "  \"total_verifications\": $total," >> "$JSON_FILE"
    echo "  \"score_conformite\": $score," >> "$JSON_FILE"
    echo "  \"resume\": {" >> "$JSON_FILE"
    echo "    \"reussies\": $count_reussi," >> "$JSON_FILE"
    echo "    \"echouees\": $count_echoue," >> "$JSON_FILE"
    echo "    \"attention\": $count_attention," >> "$JSON_FILE"
    echo "    \"info\": $count_info" >> "$JSON_FILE"
    echo "  }," >> "$JSON_FILE"
    echo "  \"resultats\": [" >> "$JSON_FILE"
    
    local first=true
    for check in "${CHECKS[@]}"; do
        IFS='|' read -r id title _ _ severity <<< "$check"
        local actual_status="${RESULTS["$id,status"]}"
        local actual_message="${RESULTS["$id,message"]}"
        
        if [ "$first" != true ]; then
            echo "," >> "$JSON_FILE"
        else
            first=false
        fi
        
        echo "    {" >> "$JSON_FILE"
        echo "      \"id_verification\": \"$id\"," >> "$JSON_FILE"
        echo "      \"titre\": \"$title\"," >> "$JSON_FILE"
        echo "      \"statut\": \"$actual_status\"," >> "$JSON_FILE"
        echo "      \"severite\": \"$severity\"," >> "$JSON_FILE"
        echo "      \"message\": \"$actual_message\"" >> "$JSON_FILE"
        echo "    }" >> "$JSON_FILE"
    done
    
    echo "  ]" >> "$JSON_FILE"
    echo "}" >> "$JSON_FILE"
}

main