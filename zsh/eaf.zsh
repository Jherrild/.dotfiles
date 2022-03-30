export EDITOR='code --wait'
export EDITOR_NOWAIT='code'
export BAT_STYLE='full'
export BAT_PAGER='less -rRXF'
export GPG_TTY=$(tty)
export FZF_CTRL_T_OPTS="--bind='enter:execute(code {})+abort' --preview 'bat --color \"always\" {}'"
export COPYFILE_DISABLE=1 # so that tar works properly on mac

export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
export PATH="$HOME/.dotfiles/aws/bin:$PATH"
export PATH="$HOME/.dotfiles/contrib/aws/bin:$PATH"
export PATH="/usr/local/opt/openssl/bin:$PATH"
export PATH="/usr/local/opt/curl/bin:$PATH"
export PATH="$PATH:/usr/local/sbin"
export MANPATH="/usr/local/man:$MANPATH"

export TZ_LIST="US/Central,US/Eastern,Europe/Warsaw,Japan"

# Colors
export GREEN='\033[0;32m'
export RED='\033[0;31m'
export NC='\033[0m'

unset JAVA_HOME

eval "$(printf 'nl="\n"')"
alias ykvault="aws-vault --prompt ykman"
alias vault="aws-vault"
alias k='kubectl'
alias c='code .'
alias v='vi .'
alias vim='nvim'
alias vi='nvim'
alias notes="$EDITOR_NOWAIT $HOME/.notes"
alias obsidian='open /Applications/Obsidian.app'
alias dotfiles="$EDITOR_NOWAIT $HOME/.dotfiles"
alias zshrc="$EDITOR_NOWAIT $HOME/.dotfiles/zsh"
alias hyper-conf="$EDITOR_NOWAIT $HOME/.dotfiles/hyper/.hyper.js"
alias mvn='./mvnw'
alias mvnw='./mvnw'
alias gradle='./gradlew'
alias gradlew='./gradlew'
alias kvers="kgp --no-headers | fzf --reverse --multi --ansi --nth 1 --preview 'kubectl get pods {1} -o json | jq -r \".spec.containers[].image\" | sed \"s/^.*\(\/\)//\" | tr -s \"[:blank:]\"'"
alias kver='kgp --all-namespaces --no-headers -o custom-columns=img:.spec.containers..image,phase:.status.phase | sort | uniq | sed "s/^.*\(\/\)//" | tr -s "[:blank:]" | column -t -s " "'
alias kverw='kgp -w --all-namespaces --no-headers -o custom-columns=img:.spec.containers..image,phase:.status.phase | sed "s/^.*\(\/\)//"'
alias klogs="kgp --no-headers | fzf --reverse --multi --ansi --nth 1 --preview 'kubectl logs --tail=30 {1} | tac | jq -C -R -r \". as \\\$line | try fromjson catch \\\$line\"'"
alias kdelete-evicted='kgp | grep Evicted | awk '"'"'{print $1}'"'"' | xargs kubectl delete pod'
alias la='ls -alh --git'
alias ls='exa'
alias ips='ps -e -o user,pid,ppid,pgid,pri,nice,%cpu,%mem,comm'
alias psi='ips | fzf --reverse --multi --ansi'
alias cat='bat'
alias ping='prettyping'
alias top='sudo htop'
alias bri='brew info'
alias bru='brew update && brew upgrade 2>&1 | tee "$HOME/.brew-upgrade.log" && brew upgrade --cask 2>&1 | tee "$HOME/.brew-upgrade-cask.log" && brew cleanup'
alias brug='brew update && brew upgrade --greedy 2>&1 | tee "$HOME/.brew-upgrade.log" && brew upgrade --cask --greedy 2>&1 | tee "$HOME/.brew-upgrade-cask.log" && brew cleanup'
alias ncdu='ncdu --color dark -rr -x --exclude .git --exclude node_modules'
alias visualvm='/Applications/VisualVM.app/Contents/MacOS/visualvm --jdkhome $JAVA_HOME'
alias jmc='/Applications/JDK\ Mission\ Control.app/Contents/MacOS/jmc -vm $JAVA_HOME/bin'
alias glg="git log --color=always --decorate=short --oneline | fzf --reverse --multi --ansi --nth 2.. --preview 'git show {+1} | delta' --bind='enter:execute(git show {1})+abort'"
alias gst="git -c color.status=always status --short | fzf --reverse --multi --ansi --nth -1 --preview 'git diff HEAD {-1} | delta' --preview-window=down:85%"
alias ghi="gh issue list | fzf --reverse --multi --ansi --preview 'gh issue view {1} | bat -p -l md --color always' --bind='enter:execute(gh issue view {1} --web)+abort' --preview-window=down:75%"
alias ghpr="gh pr list | fzf --reverse --multi --ansi --preview 'gh pr view {1} | bat -p -l md --color always' --bind='enter:execute(gh pr view {1} --web)+abort' --preview-window=down:75%"

alias hl='h ERROR INFO WARN DEBUG'
alias lzd='lazydocker'
alias trim="awk '{\$1=\$1};1'"
alias wttr="curl 'https://wttr.in/Bellevue?m'"
alias wttr+="curl 'https://v2.wttr.in/Bellevue?m'"
alias moon="curl 'https://wttr.in/Moon'"

alias docker-test='docker run docker/whalesay cowsay Hello World!'
alias docker-stop-all='docker stop $(docker ps -q)'
alias docker-rm-all='docker rm $(docker ps -aq)'
alias docker-rmi-all='docker rmi -f $(docker images -aq)'
alias docker-destroy-all='docker-stop-all && docker-rm-all && docker-rmi-all'

alias print-keystore='keytool -list -v -keystore'
alias print-cert='keytool -printcert -v -file'

alias vpn-enable='launchctl load /Library/LaunchAgents/com.paloaltonetworks.gp.pangp*'
alias vpn-disable='launchctl unload /Library/LaunchAgents/com.paloaltonetworks.gp.pangp*'

alias gradle-build-scan-enable='[ -f ~/.gradle/enterprise/keys.properties.bak ] && mv ~/.gradle/enterprise/keys.properties.bak ~/.gradle/enterprise/keys.properties'
alias gradle-build-scan-disable='[ -f ~/.gradle/enterprise/keys.properties ] && mv ~/.gradle/enterprise/keys.properties ~/.gradle/enterprise/keys.properties.bak'

function docker-rmi() {
    if [ $# -eq 1 ]; then
        docker rmi -f "$(docker images $1 -aq)"
    else
        echo "Usage: $0 <imageName>"
    fi
}

function uao() {
    if [ $# -eq 1 ]; then
        fileName=$(basename -- "$1")
        projectDirName="${fileName%.*}"
        unzip -q "$fileName"
        cd "$projectDirName"
        idea .
    else
        echo "Usage: $0 <file.zip>"
    fi
}

function kg() {
    if [ $# -eq 1 ]; then
        kubectl get $1 --no-headers --all-namespaces | fzf --reverse --multi --ansi --nth 2 --preview "kubectl get $1 {2} --namespace {1} -o yaml | bat -n -l yaml --color always" --preview-window=down:80%
    else
        echo "Usage: $0 <resource>"
    fi
}

function kd() {
    if [ $# -eq 1 ]; then
        kubectl get $1 --no-headers --all-namespaces | fzf --reverse --multi --ansi --nth 2 --preview "kubectl describe $1 {2} --namespace {1} | bat -n -l yaml --color always" --preview-window=down:80%
    else
        echo "Usage: $0 <resource>"
    fi
}

function ke() {
    pod=$(kgpa | fzf --reverse --ansi --query="$@" | awk '{print $2}')
    if [ ! -z "$pod" ]; then
        echo # so that rempote prompt appears
        kubectl exec -it "$pod" -- /bin/bash
    fi
}

function kipf() {
    if [ $# -eq 2 ]; then
        kubectl exec -it $1 -- /bin/bash -c "apt-get update && apt-get install -y socat"
        kubectl port-forward $1 $2
    else
        echo "Usage: $0 <pod> <port-mapping>"
    fi
}

function which-nodes() {
    if [ $# -eq 1 ]; then
        kubectl get pod -o=custom-columns=NODE:.spec.nodeName,NAME:.metadata.name --all-namespaces --no-headers | grep $1
    else
        kubectl get pod -o=custom-columns=NODE:.spec.nodeName,NAME:.metadata.name --all-namespaces --no-headers
    fi
}

function which-nodesi() {
    nodes=''
    if [ $# -eq 1 ]; then
        nodes=$(which-nodes $1)
    else
        nodes=$(which-nodes)
    fi

    echo $nodes | fzf --reverse --multi --ansi --preview 'kubectl get pods --all-namespaces -o=custom-columns=NODE:.spec.nodeName,NAME:.metadata.name | grep {1} | tr -s " " | cut -f2 -d" "'
}

function kchaos() {
    if [ $# -eq 2 ]; then
        kubectl get pod -o=custom-columns=NAME:.metadata.name,NODE:.spec.nodeName --no-headers | grep -v -E "$(which-nodes $1 | cut -f1 -d' ' | paste -sd '|' -)" | grep deployment | shuf | head -n$2 | cut -f1 -d' ' | xargs kubectl delete pod
    else
        echo "Usage: $0 <pod name pattern to protect> <number of pods to delete>"
    fi
}

function git-sync() {
    if [ $# -eq 0 ]; then
        git-sync "$(git_main_branch)"
    elif [ $# -eq 1 ]; then
        git fetch upstream && git checkout $1 && git merge upstream/$1
    else
        echo "Usage: $0 [<branch>]"
    fi
}

function git-rename {
    if [ $# -eq 0 ]; then
        git-rename master main
    elif [ $# -eq 2 ]; then
        git branch -m "$1" "$2"
        git fetch origin
        git branch -u origin/"$2" "$2"
        git remote set-head origin -a
    else
        echo "Usage: $0 [<branch-from> <branch-to>]"
    fi
}

function gitignore() {
    api="curl -L -s https://www.gitignore.io/api"
    if [ "$#" -eq 0 ]; then
        result="$(eval "$api/list" | tr ',' '\n' | fzf --reverse --multi --preview "$api/{} | bat -n -l gitignore --color always" | paste -s -d "," -)"
        [ -n "$result" ] && eval "$api/$result"
    else
        eval "$api/$*"
    fi
}

function full-repo-review {
    # Creating an empty branch with no history
    git checkout --orphan code-review
    git rm -r --cached '*'
    git clean -fxd

    # Empty commit so we will have some history
    git commit --allow-empty -m "Emptyness for review"
    # Creating another branch which shares the same history
    git branch empty

    # Merge main to code-review, push and we can create a PR from code-review to empty
    git merge main --allow-unrelated-histories
    git push origin code-review
    git push origin empty
}

function kms-encrypt() {
    if [ $# -eq 2 ]; then
        aws kms encrypt --key-id $1 --plaintext $2 --output text --query CiphertextBlob
    else
        echo "Usage: $0 <keyID> <plaintext>"
    fi
}

function kms-decrypt() {
    if [ $# -eq 1 ]; then
        aws kms decrypt --ciphertext-blob fileb://<(echo $1 | base64 --decode) --output text --query Plaintext | base64 --decode
    else
        echo "Usage: $0 <ciphertext> (base64 encoded, as is from encrypt)"
    fi
}

function fbn() {
    if [ $# -eq 1 ]; then
        find . -name $1
    elif [ $# -eq 2 ]; then
        find $1 -name $2
    else
        echo "Find by Name, usage: $0 [path] \"<fileNamePattern>\""
        echo "e.g.: fbn . \"*.java\""
    fi
}

function fbc() {
    if [ $# -eq 1 ]; then
        grep $1 -r .
    elif [ $# -eq 2 ]; then
        grep $1 -r . --include=$2
    else
        echo "Find by Content, usage: $0 <query> [\"fileNamePattern>\"]"
        echo "e.g.: fbc HashMap \"*.java\""
    fi
}

function killpidof() {
    if [ $# -eq 1 ]; then
        sudo kill `pidof $1`
    else
        echo "Usage: $0 <commandName>"
    fi
}

function cmdof() {
    if [ $# -eq 1 ]; then
        ps ax | grep $1
    else
        echo "Usage: $0 <commandName>"
    fi
}

function wholistens() {
    sudo lsof -PiTCP -sTCP:LISTEN
}

function docker-exec-debug() {
    if [ $# -eq 1 ]; then
        docker exec -it $1 sh
    else
        echo "Usage: $0 <imageID>"
    fi
}

function docker-run-debug() {
    if [ $# -eq 1 ]; then
        docker run -it --entrypoint sh $1
    else
        echo "Usage: $0 <containerID>"
    fi
}

function bigfiles() {
    du -sh * | gsort -rh | head -n10
}

function showHiddenFiles() {
    hiddenFiles YES
}

function hideHiddenFiles() {
    hiddenFiles NO
}

function hiddenFiles() {
    if [ $# -eq 1 ]; then
        defaults write com.apple.finder AppleShowAllFiles $1 && killall Finder
    else
        echo "Usage: $0 YES / $0 NO"
    fi
}

function colors() {
    for i in {0..255} ; do
        printf "\x1b[48;5;%sm%3d\e[0m " "$i" "$i"
        if (( i == 15 )) || (( i > 15 )) && (( (i-15) % 6 == 0 )); then
            printf "\n";
        fi
    done
}

function random() {
    if [ $# -eq 1 ]; then
        head /dev/random | base64 | head -c $1
    else
        echo "Usage: $0 <lenght>"
    fi
}

function release-notes() {
    if [ $# -eq 1 ]; then
        git log $1 --pretty=oneline | cat | grep -E 'Merge pull request .*|.*\(#\d+\).*' | cut -d' ' -f 2-
    else
        echo "Usage: $0 <revision range>"
        echo "$0 450d8c9...561d5bf"
        echo "$0 450d8c9...main"
        echo "$0 450d8c9...HEAD"
        echo "$0 1.5.x...main"
        echo "$0 1.5.0...1.5.1"
    fi
}

function pwdless() {
    if [ "$#" != 1 ]; then
        echo "Usage: $0 hostname"
    else
        echo "Setting up $1"
        cat ~/.ssh/id_rsa.pub | ssh $1 'install -D /dev/stdin ~/.ssh/authorized_keys'
    fi
}

function key-fingerprint() {
    if [ "$#" != 1 ]; then
        echo "Usage: $0 <key file path>"
    else
        openssl pkcs8 -in $1 -inform PEM -outform DER -topk8 -nocrypt | openssl sha1 -c
    fi
}

function watch-http() {
    if [ "$#" -eq 1 ]; then
        watch http --verbose --pretty=format "$1";
    elif [ "$#" -eq 2 ]; then
        watch "$1" http --verbose --pretty=format "$2";
    else
        echo "Usage: $0 [\"<watch-args>\"] \"<httpie-args>\""
        echo "Examples:"
        echo "\t$0 :8080"
        echo "\t$0 '-n1' ':8080'"
    fi
}

function wiretap() {
    if [ "$#" -eq 0 ]; then
        wiretap 8080
    elif [ "$#" -eq 1 ]; then
        echo "Listening on port $1"
        /usr/bin/nc -kl $1
    else
        echo "Usage: $0 [port]"
    fi
}

function connection-test() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <SERVER_TO_PING>";
    else
        ping -c 1 $1 #>> /dev/null 2>&1
    fi
}

function http-serv() {
    if [ $# -eq 1 ]; then
        www_dir='/tmp/www'
        mkdir -p $www_dir && echo 'Hello World!' > $www_dir/index.html
    elif [ $# -eq 2 ]; then
        www_dir=$2
    else
        echo "Usage: $0 <port> [directory]"
        return 1;
    fi
    echo "Starting HTTP Server listening on port $1, serving directory: $www_dir"
    pushd $www_dir
    python -m SimpleHTTPServer $1
    popd
    unset www_dir
}

function https-serv() {
    if [ $# -eq 1 ]; then
        www_dir='/tmp/www'
        mkdir -p $www_dir && echo 'Hello World!' > $www_dir/index.html
    elif [ $# -eq 2 ]; then
        www_dir=$2
    else
        echo "Usage: $0 <port> [directory]"
        return 1;
    fi

    echo "Starting HTTP Server listening on port $1, serving directory: $www_dir"
    pushd $www_dir
    openssl req -new -x509 -subj '/CN=Unknown/O=Unknown/C=US' -days 365 -nodes -keyout server.pem -out server.pem
    python - <<EOF
import BaseHTTPServer, SimpleHTTPServer, ssl
httpd = BaseHTTPServer.HTTPServer(('localhost', $1), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
EOF
    popd
    unset www_dir
}

function ssh-tunnel() {
    if [ "$#" -ne 2 ]; then
        echo "Usage: $0 <local-port> <host:port>";
    else
        hostAndPort=($(echo $2 | sed 's/:/ /g'))
        ssh -L $1:$hostAndPort[1]:$hostAndPort[2] -Nf $USERNAME@192.168.0.1 # change server you want the tunnel to go through
    fi
}

function me() {
    curl -s cli.fyi/me
}

function myip() {
    echo "local: $(mylocalip)"
    echo "public: $(mypublicip)"
}

function mylocalip() {
    ipconfig getifaddr en1 || ipconfig getifaddr en0
}

function mypublicip() {
    curl -s 'https://ifconfig.io'
}

function fyi() {
    api="curl -L -s -k https://cli.fyi"
    if [ "$#" -eq 0 ]; then
        result="$(eval "$api/help" | jq -r '.data | to_entries | .[] | .key + " - " + .value.example' | fzf --reverse --multi --preview "echo {} | cut -d'-' -f2- | xargs -n1 curl -L -s -k | jq -C")"
        [ -n "$result" ] && echo $result | cut -d'-' -f2- | xargs -n1 curl -L -s -k | jq -C
    else
        eval "$api/$*" | jq
    fi
}

function randomMAC() {
    # https://github.com/feross/spoof
    spoof list --wifi
    echo 'Randomizing MAC...'
    sudo spoof randomize wi-fi
    spoof list --wifi
}

function restoreMAC() {
    spoof list --wifi
    echo 'Restoring MAC...'
    sudo spoof set `cat $HOME/.sec/mac` wi-fi
    spoof list --wifi
}

function gradleVersion() {
    curl -s https://services.gradle.org/versions/current | jq '.version' --raw-output
    # groovy -e "println new groovy.json.JsonSlurper().parseText('https://services.gradle.org/versions/current'.toURL().text).version"
}

function gradlewUpdate() {
    ./gradlew wrapper --gradle-version `gradleVersion`
}

function clipboard-fix() {
    echo 'restarting clipboard services...'
    killall pbs
    killall pboard
    launchctl start com.apple.pboard
    launchctl start com.apple.pbs
    killall Finder
    echo 'please restart your apps'
}

function dns-flush() {
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder
}

function update() {
    echo 'zsh upgrade...'
    "$ZSH/tools/upgrade.sh"
    zinit self-update
    zinit update --parallel

    echo 'brew update, upgrade, cleanup...'
    brew update
    brew upgrade #--greedy
    brew upgrade --cask
    brew cleanup

    echo 'tldr update...'
    tldr --update

    echo 'asdf plugin-update...'
    asdf plugin-update --all

    echo 'npm update...'
    npm update npm -g && npm update -g

    echo 'softwareupdate update...'
    softwareupdate -i -a
}

function install-completions() {
    # first create completion file, e.g.: kind completion zsh > /usr/local/share/zsh/site-functions/_kind
    autoload -U compinit && compinit
}

function brew-link-fix {
    brew link --overwrite docker
    brew link --overwrite docker-completion
    brew link --overwrite docker-compose

    rm /usr/local/bin/gpg2
    ln -s /usr/local/bin/gpg /usr/local/bin/gpg2
}

function demo-init() {
    cp -r "$HOME/.dotfiles/demo-initializer/." .
    git init
    git add .
    git commit -m 'initial demo project'
}

function refresh-bluesky() {
    # Refresh and verify VPN
    sudo -E infractl vpn refresh -c bluesky
    sudo -E infractl vpn check -c bluesky
    
    # Generate Bluesky config
    infractl cell kubeconfig-get -c bluesky -R developer -f
}

refresh-access() {
    sudo -E infractl vpn check -c bluesky

    # Refresh and verify VPN
    echo "Connecting to infractl VPN..."
    sudo -E infractl vpn refresh -c bluesky
    #sudo -E infractl vpn disconnect -A

    # If refresh fails, then connect
    if [ $? -eq 0 ]; then
        sudo -E infractl vpn connect -c bluesky
    fi

    #sudo -E infractl vpn connect -A
    sudo -E infractl vpn check -c bluesky
    #sudo -E infractl vpn check -A​

    echo "Creating cell kubeconfigs for developer role..."
    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        ykvault exec olympus -- infractl cell kubeconfig-get -c bluesky -R developer -f
    else
        vault exec olympus -- infractl cell kubeconfig-get -c bluesky -R developer -f
    fi
    #vault exec olympus -- infractl cell kubeconfig-get -t development -R developer

    echo "Logging into ecr..."
    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        ykvault exec olympus -- infractl aws ecr-login
    else
        vault exec olympus -- infractl aws ecr-login
    fi
}

function login-ecr() {
    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        ykvault exec olympus -- infractl aws ecr-login
    else
        vault exec olympus -- infractl aws ecr-login
    fi
}

function stack-id() {
    if [[ $1 == "" ]]; then
        kubectl get stacks | fzf | awk '{print $3}'
    else
        kubectl get stacks | fzf -e -f $1 | awk '{print $3}'
    fi
}

function stack-name() {
    if [[ $1 == "" ]]; then
        kubectl get stacks | fzf | awk '{print $4}'
    else
        kubectl get stacks | fzf -e -f $1 | awk '{print $4}'
    fi
}

function stacks() {
    kubectl get stacks | fzf
}

function pods() {
    stack_name=$(stack-name)
    kubectl get pod -n $stack_name | fzf
}

function channels() {
    kubectl get channels | fzf
}

# Displays available kube configs, and allows one to be selected
function kconfig() {
    kube_home="$HOME/.kube"

    if [[ "$1" != "" ]]; then
        config_name=$(ls $kube_home | grep -v "cache" | fzf -e -f "$*")
    else
        config_name=$(ls $kube_home | grep -v "cache" | fzf --reverse --preview "bat -p -l yaml --color always $kube_home/{}")
    fi
    
    if [[ "$config_name" != "" ]]; then
        export KUBECONFIG="$kube_home/$config_name"
    fi
}

# Prompts ykman for an mfa token for the active AWS account, and prints it to the screen
function mfa() {
    ykman oath accounts code arn:aws:iam::${ACCOUNT_ID}:mfa/${whoami} | awk '{print $2}'
}

# Refreshes access token and prints to screen
function token() {
    export ACCESS_TOKEN=$(curl -s -X POST https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize\?refresh_token\=$CSP_TOKEN | jq -r '.access_token')
    export Token=$ACCESS_TOKEN
    echo $ACCESS_TOKEN
}

# Curls and prints the response in pretty print json
function pcurl() {
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color
    
    response=$(curl "$@")
    http_status=$(echo $response | fzf -e -f "HTTP/2")
    pattern="20"

    echo "\n\t"
    if [[ $http_status == *$pattern* ]]; then
        echo "${GREEN}$http_status${NC}"
    else
        echo "${RED}$http_status${NC}"
    fi
    echo "\n"

    echo $response | jq -R 'fromjson? | .' | bat -n -l json --color always
}

function get-clustergroups() {
    # Get json and downcase top level keys
    cluster_group_uri="https://$(whoami).tmc-dev.cloud.vmware.com/v1alpha/clustergroups"
    api="curl -X GET $cluster_group_uri -H \"Authorization: Bearer $ACCESS_TOKEN\" --insecure -L -s"
    json=$(eval $api | jq '. | with_entries( .key |= ascii_downcase )')

    # Try alternative URI on failure
    if [[ "$json" == *"Not Found"* ]]; then
        cluster_group_uri="https://$(whoami).tmc-dev.cloud.vmware.com/v1alpha1/clustergroups"
        api="curl -X GET $cluster_group_uri -H \"Authorization: Bearer $ACCESS_TOKEN\" --insecure -L -s"
        json=$(eval $api | jq '. | with_entries( .key |= ascii_downcase )')
    fi
    
    # Parse out cluster groups
    echo $json | jq '. | .clustergroups[] | .fullName | .name' | tr -d '"' | fzf --reverse --multi --preview "jq '. | .clustergroups[] | select(.fullName.name==\"{}\")' <(echo '$json') | bat -n -l json --color always"
}

function get-clusters() {
    cluster_uri="https://$(whoami).tmc-dev.cloud.vmware.com/v1alpha1/clusters"
    if [[ "$1" == "" ]]; then
        api="curl -X GET $cluster_uri -H \"Authorization: Bearer $ACCESS_TOKEN\" --insecure -L -s"
    else
        api="curl -X GET $1 -H \"Authorization: Bearer $ACCESS_TOKEN\" --insecure -L -s"
    fi
    
    json=$(eval $api | jq .) #| bat -n -l json --color always
    echo $json | jq '.clusters[] | .fullName | .name' | tr -d '"' | fzf --reverse --multi --preview "jq '.clusters[] | select(.fullName.name==\"{}\")' <(echo '$json') | bat -n -l json --color always"
}

function get-lock() {
    # First select namespace
    namespace=$(sheepctl namespace list | grep '^| [a-zA-Z0-9]' | awk -F '|' '{print $2}' | tr -d ' ' | fzf --reverse --multi --preview 'sheepctl pool list -n {}')
    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    # Select pool from namespace
    pool=$(sheepctl pool list -n $namespace | grep '^| [a-zA-Z0-9]' | fzf | awk -F '|' '{print $2}' | tr -d ' ')
    if [[ "$pool" == "" ]]; then
        return 0
    fi

    # Newline    
    echo

    # Get duration
    vared -p "Duration: " -c duration
    if [[ "$duration" == "" ]]; then
        return 0
    fi

    # Lock environment
    random_id=$(uuidgen)
    random_id_file_name="$HOME/.locks/$random_id.json"
    sheepctl pool lock -n $namespace --lifetime $duration $pool -o $random_id_file_name

    # Generate correct lock file name
    lock_id=$(cat $random_id_file_name | jq '.id' -r)
    lock_id_file_name="$HOME/.locks/$lock_id.json"

    # Rename lock file
    mkdir -p "$home/.locks"
    mv $random_id_file_name $lock_id_file_name

    # Export kube config
    pool_name=$(cat $lock_id_file_name | jq '.pool_name' -r)
    kube_config_file_name="$HOME/.kube/$pool_name-$lock_id"
    cat $lock_id_file_name | jq '.access | fromjson | .kubeconfig.management.config' -r > $kube_config_file_name
}

function update-lock() {
    lock_file="$HOME/.locks/$1"

    # Get lock info
    lock_id=$(cat $lock_file | jq '.id' -r)
    namespace_id=$(cat $lock_file | jq '.namespace_id' -r)

    sheepctl lock get -n $namespace_id $lock_id -o $lock_file > /dev/null 2>&1
}

function locks() {
    # Known Good
    #lock_file_name=$(ls "$HOME/.locks" | fzf --reverse --preview "bat -p -l json --color always $HOME/.locks/{}")
    #lock_file_name=$(ls "$HOME/.locks" | fzf --reverse --preview "$(export filename=\"$HOME/.locks/{}\" ; export lock_id=$(cat $filename | jq '.id' -r) ; export namespace_id=$(cat $filename | jq '.namespace_id' -r) ; $(sheepctl lock get -n $namespace_id $lock_id -o $filename) > /dev/null 2>&1) | bat -p -l json --color always $filename")
    
    lock_file_name=$(ls "$HOME/.locks" | fzf --reverse --preview "source /$HOME/.dotfiles/zsh/eaf.zsh ; update-lock {} | bat -p -l json --color always $HOME/.locks/{}")
    lock_file="$HOME/.locks/$lock_file_name"
    if [[ "$lock_file_name" == "" ]]; then
        return 0
    fi

    # Get lock info
    lock_id=$(cat $lock_file | jq '.id' -r)
    namespace_id=$(cat $lock_file | jq '.namespace_id' -r)
    lock_status=$(cat $lock_file | jq '.status' -r)

    # Get valid operation based on state
    if [[ "$lock_status" == "" ]]; then
        return 1
    elif [[ "$lock_status" == "locked" ]]; then
        operation=$(echo "extend\nonboard\ndelete\ncancel" | fzf --reverse)
    elif [[ "$lock_status" == "expired" ]]; then
        operation=$(echo "delete\ncancel" | fzf --reverse)
    fi

    if [[ "$operation" == "" ]]; then
        return 0
    fi
    
    # Get kubeconfig file info
    kube_config_file_name=$(ls "$HOME/.kube" | grep $lock_id)
    kube_config_file="$HOME/.kube/$kube_config_file_name"
    echo

    # Perform extend/delete operation
    if [[ $operation == "delete" ]]; then
        vared -p "Confirm Delete[y/n]? " -c REPLY

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [[ "$lock_status" == "locked" ]]; then
                sheepctl lock delete -n $namespace_id $lock_id
            fi

            echo "Checking if management cluster has been onboarded..."
            get-managementcluster-by-lock-id $lock_id

            # If a matching lock is found, delete it
            if [ $? -eq 0 ]; then
                delete-managementcluster-by-lock-id $lock_id
                
                #remove-tkgm-cluster $(whoami) $cluster_name 
                if [ $? -eq 1 ]; then
                    return 1
                fi
            fi

            # Update lock again, and delete files if expired
            update-lock $lock_file_name
            lock_status=$(cat $lock_file | jq '.status' -r)
            if [[ $lock_status == "expired" ]]; then

                echo "Lock is expired, removing files..."
                
                echo "Removing lock file: $lock_file"
                rm $lock_file

                echo "Removing cube config: $kube_config_file"
                rm $kube_config_file
            fi
        fi
    elif [[ $operation == "extend" ]]; then
        vared -p "Extension duration: " -c extension_time
        sheepctl lock extend -n $namespace_id $lock_id --add -t $extension_time
    elif [[ $operation == "onboard" ]]; then
        cluster_group=$(get-clustergroups)
        pool_name=$(cat $lock_file | jq '.pool_name' -r)
        if [[ "$pool_name" == "" ]]; then
            echo "${RED}Pool name could not be extracted from lock file${NC}"
            return 1
        fi

        cluster_name="$pool_name-$lock_id"
        echo "Creating cluster $cluster_name..."

        if [[ "$cluster_group" == "" ]]; then
            echo "${RED}Cluster group must be specified${NC}"
            return 1
        fi

        # Onboard
        installer_uri=$(add-managementcluster-by-lock-id $cluster_name $cluster_group | jq -e -r '.managementCluster.status.registrationUrl')

        if [ $? -eq 1 ]; then
            echo "Unable to get installer URI"
            return 1
        fi

        kconfig "$kube_config_file_name"
        kubectl apply -f "$installer_uri"
    elif [[ $operation == "cancel" ]]; then
        return 0
    fi
}

function add-managementcluster-by-lock-id() {
    cluster_name=$1
    cluster_group=$2

    curl --location --request POST "https://$(whoami).tmc-dev.cloud.vmware.com/v1alpha1/managementclusters" \
        --header "Authorization: Bearer $ACCESS_TOKEN" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-raw "{
            \"managementCluster\": {
                \"fullName\": {
                    \"name\": \"$cluster_name\"
                },
                \"spec\": {
                    \"kubernetesProviderType\": \"VMWARE_TANZU_KUBERNETES_GRID\",
                    \"defaultClusterGroup\": \"$cluster_group\"
                }
            }
        }"
}

function delete-managementcluster-by-lock-id() {
    domain=$(whoami)
    lock_id=$1
    cluster_name=$(get-managementcluster-by-lock-id $lock_id)

    if [ $? -eq 1 ]; then
        echo $cluster_name
        return 1
    fi

    output=$(curl --location --request DELETE "https://$domain.tmc-dev.cloud.vmware.com/v1alpha1/managementclusters/$cluster_name" \
        --header "Authorization: Bearer $ACCESS_TOKEN" \
        --header 'Accept: application/json')

    if [ $? -eq 1 ]; then
        echo "${RED}Failed to delete management cluster '$cluster_name':${NC}"
        echo $output
        return 1
    elif [[ "$output" == *"error"* ]]; then
        echo "${RED}Failed to delete management cluster '$cluster_name':${NC}"
        echo $output
        return 1
    else
        echo $output | jq '.'
    fi
}

function get-managementcluster-by-lock-id() {
    search_term=$1
    uri="https://$(whoami).tmc-dev.cloud.vmware.com/v1alpha1/managementclusters"
    api="curl -X GET $uri -H \"Authorization: Bearer $ACCESS_TOKEN\" --insecure -L -s"
    json=$(eval $api | jq '. | with_entries( .key |= ascii_downcase )')

    # Parse out cluster groups
    output=$(echo $json | jq '. | .managementclusters[] | .fullName | .name' | tr -d '"' | fzf -e -f $1)

    if [[ "$output" == "" ]]; then
        echo "${RED}No matching management clusters found${NC}"
        echo "$output"
        return 1
    elif [[ "$output" == *"$nl"* ]]; then
        echo "${RED}More than one matching management cluster found:\n${NC}"
        echo "$output"
        return 1
    else
        echo $output
    fi
}

function pods() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf --preview "$(echo "{}" | awk '{print $1}')" | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    if [[ "$2" != "" ]]; then
        pods=$(k get pods -n $namespace | fzf -e -f "$2" | awk '{print $1}' | tr '\n' ' ')
    else
        pods=$(k get pods -n $namespace | fzf --multi | awk '{print $1}' | tr '\n' ' ')
    fi

    if [[ "$pods" == "" ]]; then
        return 0
    fi

    # Delete pod
    echo $pods
}

function restart-pod() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    if [[ "$2" != "" ]]; then
        pods=$(k get pods -n $namespace | fzf -e -f "$2" | awk '{print $1}' | tr '\n' ' ')
    else
        pods=$(k get pods -n $namespace | fzf --multi | awk '{print $1}' | tr '\n' ' ')
    fi

    if [[ "$pods" == "" ]]; then
        return 0
    fi

    # Delete pod
    k delete pods -n $namespace $(echo $pods)
}

function listen-pod() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    if [[ "$2" != "" ]]; then
        pod=$(k get pods -n $namespace | fzf -e -f "$2" | awk '{print $1}')
    else
        pod=$(k get pods -n $namespace | fzf | awk '{print $1}')
    fi

    if [[ "$pod" == "" ]]; then
        return 0
    fi
    
    k logs -n $namespace $pod -f --since "10m"
}

function describe-pod() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    if [[ "$2" != "" ]]; then
        pod=$(k get pods -n $namespace | fzf -e -f "$2" | awk '{print $1}')
    else
        pod=$(k get pods -n $namespace | fzf | awk '{print $1}')
    fi

    if [[ "$pod" == "" ]]; then
        return 0
    fi
    
    k describe -n $namespace pod $pod
}

function watch-pod() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        echo "${RED}Not found${NC}" 
        return 0
    fi

    echo $namespace

    #k get pod -n $namespace -o yaml | fzf -e -f imageID | awk '{print $2}' | tr '/' ' ' | awk '{print $4}'
    #while [[ $(k get pod -n vmware-system-tmc | fzf -e -f retriever | awk '{print $2}' | k get pod -n vmware-system-tmc -o yaml | fzf -e -f imageID | fzf -e -f resource-retriever) == *"d5f8409f48ff1ce7d7d55c3460a4e29562e2e514"*  ]]; do; sleep 5; done; afplay /System/Library/Sounds/Blow.aiff; echo "\n\n\nNew version '' detected\n\n\n"
}

function stack-config() {
    # Check that access token is stored in variable 
    if [[ "$GITLAB_ACCESS_TOKEN" == "" ]]; then
        echo "Required environment variable GITLAB_ACCESS_TOKEN is not set- please visit 'https://gitlab.eng.vmware.com/-/profile/personal_access_tokens?name=Repository+Access+token&scopes=read_repository' to generate a gitlab repository read access token, set the afformentioned variable in your environment, and rerun."
        return 1
    fi
    
    # Check that stack config variable is set
    if [[ "$STACK_CONFIG" == "" ]]; then
        echo "Required environment variable STACK_CONFIG is not set- please export the location of your stack config yaml file and rerun."
        return 1
    fi

    # Check file exists
    touch $STACK_CONFIG > /dev/null 2>&1
    if [[ $? == 1 ]]; then
        echo "Environment file '$STACK_CONFIG' is missing or unreadable"
        return 1
    fi

    # Set channel_tag variable, exit if it is missing from file
    local channel_tag=$(cat $STACK_CONFIG | yq '.spec.channel' 2>/dev/null)
    if [[ "$channel_tag" == "null" ]]; then
        echo "'channel' tag is missing from file '$STACK_CONFIG'"
        return 1
    fi

    # Pick operation, exit if selection is canceled
    local operation=$(echo "add\ndelete\nupdate\ncancel" | fzf --reverse)
    if [[ "$operation" == "" ]]; then
        return 0
    fi

    # Perform extend/delete operation
    if [[ $operation == "add" ]]; then
        templateYamlFile="$HOME/TEMP/$channel_tag.yaml"
        curl -X GET "https://gitlab.eng.vmware.com/api/v4/projects/23995/repository/files/channels%2Fdev%2F$channel_tag.yaml/raw" --header "PRIVATE-TOKEN: $GITLAB_ACCESS_TOKEN" | yq '.' > $templateYamlFile
        key_path=$(traverse-yaml-file $templateYamlFile)
    elif [[ $operation == "delete" ]]; then
        # TODO: Implement
    elif [[ $operation == "update" ]]; then
        key_path=$(traverse-yaml-file $STACK_CONFIG)
        
    elif [[ $operation == "cancel" ]]; then
        return 0
    fi
}

function is-leaf() {
    $(cat $1 | yq "$2 | keys" > /dev/null 2>&1)
}

function traverse-yaml-file() {
    if [[ "$1" == "" ]]; then
        echo "${RED}No input file specified${NC}"
        return 1
    else
        yaml=$1
    fi

    keys=$(cat $yaml | yq ". | keys")
    local key_path="."

    while [[ "$value" == "" ]]; do
        # first loop
        if [[ "$key_path" == "." ]]; then
            local key_path="."$(cat $yaml | yq "$key_path | keys" | awk '{print $2}' | fzf --reverse --preview "cat $yaml | yq -C '$key_path{}'")
        else
            local key_path="$key_path."$(cat $yaml | yq "$key_path | keys" | awk '{print $2}' | fzf --reverse --preview "cat $yaml | yq -C '$key_path.{}'")
        fi

        # Check to see if user broke loop or selected nothing
        if [[ $? -eq 1 ]]; then
            return 1
        elif [[ "$key_path" == *"." ]]; then
            return 0
        fi

        # Later loops
        if $(is-leaf $yaml $key_path) ; then
        else
            local value=$(cat $yaml | yq "$key_path")
        fi
    done
    
    echo $key_path
}