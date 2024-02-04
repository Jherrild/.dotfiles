#   components:
#   - name: managed-k8s-provider
#     revision: 09e53b5021ded77b372db9a1b94e893fdfa91519
#     sourceImage: 498533941640.dkr.ecr.us-west-2.amazonaws.com/managed-k8s-provider/config-dev

# Tanzu
export EKSCLUSTER_TEST_CONFIG=/Users/jherrild/repos/cli-plugins/artifacts/darwin/amd64/cli/pekscluster/dev/test/manageconfig.yaml
alias ekscluster="/Users/jherrild/repos/cli-plugins/artifacts/darwin/amd64/cli/ekscluster/dev/tanzu-ekscluster-darwin_amd64"
alias pekscluster="/Users/jherrild/repos/cli-plugins/artifacts/darwin/amd64/cli/pekscluster/dev/tanzu-pekscluster-darwin_amd64"

# Terraform ENV
export VMW_CLOUD_ENDPOINT=console-stg.cloud.vmware.com
export TMC_ENDPOINT=jherrild.stacks.bluesky.tmc-dev.cloud.vmware.com
export TMC_HOST=$TMC_ENDPOINT
export VMW_CLOUD_API_TOKEN=$CSP_TOKEN

export EDITOR='code --wait'
export EDITOR_NOWAIT='code'
export BAT_STYLE='full'
export BAT_PAGER='less -rRXF'
export GPG_TTY=$(tty)
export FZF_CTRL_T_OPTS="--bind='enter:execute(code {})+abort' --preview 'bat --color \"always\" {}'"
export COPYFILE_DISABLE=1 # so that tar works properly on mac

# Go variables
#export GOPATH="/usr/local/Cellar/go@1.16/1.16.15"
export GOSUMDB=off
export GOPROXY=direct
# export GOPATH="/usr/local/Cellar/go/1.20.6"
export GOPATH="$HOME/go"
export GOROOT="$(brew --prefix go)/libexec"
export PATH="$GOROOT:$GOPATH/bin:$PATH"
#export GOPRIVATE=http://gitlab.eng.vmware.com
export GOPRIVATE="*.vmware.com,github.com/vmware-tanzu-private*"

export PATH="$HOME/.dotfiles/aws/bin:$PATH"
export PATH="$HOME/.dotfiles/contrib/aws/bin:$PATH"
export PATH="/Applications/GoLand.app/Contents/MacOS:$PATH"
export PATH="/usr/local/opt/openssl/bin:$PATH"
export PATH="/usr/local/opt/curl/bin:$PATH"
export PATH="/usr/local/sbin:$PATH"
export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
export MANPATH="/usr/local/man:$MANPATH"

# PSQL
export PSQL_VERSION=$(ls /usr/local/Cellar/libpq)
export PATH="/usr/local/Cellar/libpq/$PSQL_VERSION/bin:$PATH"
# export PATH="/usr/local/Cellar/libpq/15.1/bin:$PATH"

# AWS
export AWS_DEFAULT_REGION=us-west-2
export AWS_ENV_OLYMPUS="olympus"
export AWS_ENV_EKS_TEST="eks-test"
export AWS_ENV_TEST_01="tmc-tests-01"
export AWS_ENV_TEST_04="tmc-tests-04"
export AWS_ENV_TEST_05="tmc-tests-05"
export AWS_ENV=$AWS_ENV_EKS_TEST

export test_05_id="AKIATQB2BFXK4WCFD3P4"
export test_05_secret="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"

# TIMEZONES
export TZ_LIST="US/Central,US/Eastern,Europe/Warsaw,Japan"

# Colors
export GREEN='\033[0;32m'
export RED='\033[0;31m'
export NC='\033[0m'

unset JAVA_HOME

eval "$(printf 'nl="\n"')"
alias eaf="code $HOME/.dotfiles/zsh/eaf.zsh"
alias zshrc="code $HOME/.zshrc"
alias vault="aws-vault"
alias k='kubectl'
# alias kubectl='kubectl-exec'
alias c='code .'
alias v='vi .'
alias vim='nvim'
alias vi='nvim'
alias notes="$EDITOR_NOWAIT $HOME/.notes"
alias obsidian='open /Applications/Obsidian.app'
alias dotfiles="$EDITOR_NOWAIT $HOME/.dotfiles"
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

function export-test-creds() {
    export ASSUME_ROLE_ARN="arn:aws:iam::919197287370:role/EKSCrossAccount"
    export AWS_ACCESS_KEY_ID=$test_05_id
    export AWS_SECRET_ACCESS_KEY=$test_05_secret
}

function ykvault() {
    aws-vault --prompt ykman $@
}

function ykgate() {
    mfa
    infractl aws login -c bluesky 
}

function get-aws-env() {
    printenv | grep "AWS_ENV_" | tr '=' ' ' | awk '{print $2}' | fzf
}

function switch-aws() {
    env=$(get-aws-env)
    export AWS_ENV=$env
}

function aws-exec() {
    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        ykvault exec $AWS_ENV -- aws $@
    else
        vault exec $AWS_ENV -- aws $@
    fi
}

# function kubectl-exec() {
#     if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
#         ykvault exec $AWS_ENV -- kubectl $@
#     else
#         vault exec $AWS_ENV -- kubectl $@
#     fi
# }

function aws-whoami() {
    aws-exec sts get-caller-identity
}

function aws-assume-role() {
    switch-aws
    role_arn=$(aws-exec iam list-roles | grep Arn | tr -d '"' | tr -d ',' | awk '{print $2}' | fzf)
    vared -p "Session name:" -c session_name
    # jsonOutput=$(aws-exec sts assume-role --role-arn $role_arn --duration-seconds 900 --role-session-name $session_name)
    jsonOutput=$(aws sts assume-role --role-arn $role_arn --duration-seconds 900 --role-session-name $session_name)
    
    # Save old variables
    export AWS_ACCESS_KEY_ID_BAK=$AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY_BAK=$AWS_SECRET_ACCESS_KEY
    export AWS_SESSION_TOKEN_BAK=$AWS_SESSION_TOKEN

    # Export new variables
    export AWS_ACCESS_KEY_ID=$(echo $jsonOutput | jq .Credentials.AccessKeyId | tr -d '"')
    export AWS_SECRET_ACCESS_KEY=$(echo $jsonOutput | jq .Credentials.SecretAccessKey | tr -d '"')
    export AWS_SESSION_TOKEN=$(echo $jsonOutput | jq .Credentials.SessionToken | tr -d '"')
    expiration=$(echo $jsonOutput | jq .Credentials.Expiration | tr -d '"')
    export AWS_SESSION_EXPIRATION=$(gdate --date="$expiration" +%s)
}

function aws-revert-role() {
    export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID_BAK
    export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY_BAK
    export AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN_BAK
    unset AWS_SESSION_EXPIRATION
}

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

function git-add() {
    git add $(echo $(gst | awk '{print $2}' | tr '\n' ' '))
}

function add-and-commit() {
    git-add
    vared -p "Commit message: " -c message
    git commit -m $message
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
    sudo -E infractl vpn disconnect -c bluesky
    sudo -E infractl vpn connect -c bluesky
    sudo -E infractl vpn check -c bluesky
    
    # Generate Bluesky config
    infractl cell kubeconfig-get -c bluesky -R developer -f
}

function refresh-whitesand() {
    # Refresh and verify VPN
    sudo -E infractl vpn disconnect -c whitesand
    sudo -E infractl vpn connect -c whitesand
    sudo -E infractl vpn check -c whitesand
    
    # Generate Bluesky config
    infractl cell kubeconfig-get -c whitesand -R poweruser -f
}

function vpn-init() {
    infractl vpn init -A
}

function refresh-access() {
    cell="bluesky"
    level="poweruser"
    if [[ $1 != "" ]]; then
        cell=$1
    fi

    if [[ $cell == "bluesky" ]]; then
        level="developer"
    fi

    echo "Connecting to infractl VPN..."
    if [[ $1 == "-a" ]]; then
        sudo -E infractl vpn disconnect -A
        sudo -E infractl vpn connect -A
        sudo -E infractl vpn check -A

        echo "Creating cell kubeconfigs for $level role..."
        if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
            infractl cell kubeconfig-get -t production -R $level -f
        else
            infractl cell kubeconfig-get -t production -R $level -f
        fi
    else
        sudo -E infractl vpn disconnect -c $cell
        sudo -E infractl vpn connect -c $cell
        sudo -E infractl vpn check -c $cell

        echo "Creating cell kubeconfigs for $level role..."
        if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
            infractl cell kubeconfig-get -c $cell -R $level -f
        else
            infractl cell kubeconfig-get -c $cell -R $level -f
        fi
    fi
}

function login-cell() {
    cell=$(infractl cell list | fzf)
    level=$(echo "developer\npoweruser\nreadonly" | fzf)

    echo "Creating cell kubeconfigs for $level role..."
    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        infractl cell kubeconfig-get -c $cell -R $level -f
    else
        infractl cell kubeconfig-get -c $cell -R $level -f
    fi
}

function login-ecr() {
    

    if [[ "$(ykman list | wc -l)" -ge "1" ]]; then
        infractl aws ecr-login
        # ykvault exec tmc-tests-05 --region us-east-1 -- aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
        # ykvault exec tmc-tests-05 --region us-east-1 -- aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 240639880661.dkr.ecr.us-east-1.amazonaws.com
        # ykvault exec olympus --region us-east-1 -- aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 702834246803.dkr.ecr.us-west-2.amazonaws.com
    else
        infractl aws ecr-login
        # vault exec tmc-tests-05 --region us-east-1 -- aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
        # vault exec tmc-tests-05 --region us-east-1 -- aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 240639880661.dkr.ecr.us-east-1.amazonaws.com
        # vault exec olympus --region us-east-1 -- aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 702834246803.dkr.ecr.us-west-2.amazonaws.com
    fi
}

function aws-portal() {
    if [[ $1 == "" ]]; then
        ykvault login $(get-aws-env) --region us-west-2
    else
        ykvault login $1 --region us-west-2
    fi
}

function stacks() {
    if [[ $1 == "" ]]; then
        kubectl get stacks | fzf
    else
        kubectl get stacks | fzf -e -f $1
    fi
}

function stack-id() {
    stacks $1 | awk '{print $3}'
}

function stack-name() {
    stacks $1 | awk '{print $4}'
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

    config_name=$(echo $config_name | awk '{print $1}')
    
    if [[ "$config_name" != "" ]]; then
        export KUBECONFIG="$kube_home/$config_name"
    fi
}

# Prompts ykman for an mfa token for the active AWS account, and prints it to the screen
function mfa() {
    DEVICE_SERIAL=$(ykman list | fzf | awk '{print $NF}')
    ACCOUNT=$(ykman --device $DEVICE_SERIAL oath accounts list | fzf)
    export MFA_CODE=$(ykman --device $DEVICE_SERIAL oath accounts code $ACCOUNT | awk '{print $NF}')
    echo $MFA_CODE
}

function ykrotate() {
    account=$(ykman oath accounts list | fzf)
    ykman oath accounts delete $account
    ykman oath accounts add $account
}

# Refreshes access token and prints to screen
function token() {
    export ACCESS_TOKEN=$(curl -X POST -H "Content-Type: application/x-www-form-urlencoded" https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize -d refresh_token=$CSP_TOKEN | jq -r '.access_token')
    export token=$ACCESS_TOKEN
    echo $ACCESS_TOKEN
}

# Gets a token for tmc-ucp-cluster-onboarding
function ucp-token() {
    export ACCESS_TOKEN=$(curl -X POST -H "Content-Type: application/x-www-form-urlencoded" https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize -d refresh_token=CklzOafHr1lWn0e4gU4Rs6yBozAOl2dSlgEjtPV6y3zDEJKdbzoKgX8Vf2_FNS5A | jq -r '.access_token')
    export token=$ACCESS_TOKEN
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

    if [[ "$(echo $json | tr -d ' ')" == "" ]]; then
        echo "Unable to list cluster groups"
        return 1
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

function pods_depricated() {
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
    
    k logs -n $namespace $pod -f --since "24h"
}

function scan-pod() {
    if [[ "$1" == "-A" ]]; then
            namespace=$1
    elif [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    if [[ "$2" != "" ]]; then
        reg=${@:2}
    else
        echo "Scan regex: "
        read reg
    fi

    if [[ "$namespace" == "-A" ]]; then
        stern -A $reg
    else
        stern -n $namespace $reg
    fi    

}

function k8s() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi
    
    stern -n $namespace k8s
}

function create() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi
    
    stern -n $namespace create
}

function attach() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi
    
    stern -n $namespace attach
}

function plisten-pod() {
    if [[ "$1" != "" ]]; then
        listen-pod | jq --arg SEARCH $1 -R '. as $line | try (fromjson) catch $line | select( . | contains($SEARCH))'
    else
        listen-pod | jq -R '. as $line | try (fromjson) catch $line'
    fi

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

# Listens to pod logs, and makes a sound when the log stream ends- intended to indicate when a pod has been restarted/updated
function watch-pod() {
    listen-pod; afplay /System/Library/Sounds/Blow.aiff
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

function wait-version() {
    repo_name=$(basename -s .git `git config --get remote.origin.url`)

    if [[ $repo_name == "workload-cluster-manager" ]] {
        cmd='docker pull 498533941640.dkr.ecr.us-west-2.amazonaws.com/workload-cluster-manager/config-dev:$(git rev-parse head)'
    }

    while [[ ! $(docker pull 498533941640.dkr.ecr.us-west-2.amazonaws.com/workload-cluster-manager/config-dev:$(git rev-parse head)) ]] {; sleep 10 }; afplay /System/Library/Sounds/Blow.aiff; git rev-parse head
}

function ding() {
    afplay /System/Library/Sounds/Blow.aiff
}

function stacks() {
    if [[ $1 == "" ]]; then
        kubectl get stacks | fzf
    else
        kubectl get stacks | fzf -e -f $1
    fi
}

function connect_psql() {
    namespace=$(stacks | awk '{print $5}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | fzf |awk '{print $1}')
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "\dt;"
    psql $url -P expanded=on
}

function connect_psql_dev() {
    namespace=$(stacks | awk '{print $4}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | fzf |awk '{print $1}')
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "\dt;"
    psql $url -P expanded=on
}

function credentials() {
    namespace=$(stacks | awk '{print $4}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | awk '{print $1}' | grep "account-manager")
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "select name, phase from credentials;"
}

function lambdas() {
    namespace=$(stacks | awk '{print $4}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | awk '{print $1}' | grep "managed-k8s")
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "SELECT full_name->'name' AS Name, full_name->'credential_name' AS Credential, status->'phase' as Phase, (case when status->>'phase' != 'READY' then status->'conditions'->'Ready'->>'reason' end) AS Error_reason, (case when status->>'phase' != 'READY' then status->'conditions'->'Ready'->>'message' end) AS Error_message FROM management_plane;"
}

function eks_clusters() {
    namespace=$(stacks | awk '{print $4}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | awk '{print $1}' | grep "managed-k8s")
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "SELECT full_name->'name' AS Name, full_name->'credential_name' AS Credential, status->'phase' as Phase, (case when status->>'phase' != 'READY' then status->'conditions'->'Ready'->>'reason' end) AS Error_reason, (case when status->>'phase' != 'READY' then status->'conditions'->'Ready'->>'message' end) AS Error_message FROM eks_cluster;"
}

function tables() {
    namespace=$(stacks | awk '{print $4}')
    creds=$(kubectl get secrets -n $namespace | grep postgres-creds | awk '{print $1}' | grep "managed-k8s")
    url=$(kubedecode $creds $namespace | grep PGURL | awk '{print $2}' | sed 's/?application_name=root_connection//g')

    psql $url -c "\dt;"
}

function get-running-job() {
    k get job -o yaml -n tmc-jherrild $(k get jobs -n tmc-jherrild --no-headers=false | aws '{print $1}')
}

function cluster-kconfig() {
    region="us-west-2"
    if [ $# -eq 1 ]; then
        region="$1"
    fi

    cluster_name=$(aws-exec eks list-clusters --region $region | jq '.clusters | .[]' -r | fzf)
    aws-exec eks update-kubeconfig --region $region --name $cluster_name --kubeconfig /Users/jherrild/.kube/$cluster_name
}

function delete-job() {
    if [[ "$1" != "" ]]; then
        namespace=$(k get namespace | fzf -e -f "$1" | awk '{print $1}')
    else
        namespace=$(k get namespace | fzf | awk '{print $1}')
    fi

    if [[ "$namespace" == "" ]]; then
        return 0
    fi

    jobs=$(k get jobs.batch -n $namespace | fzf --multi | awk '{print $1}' | tr '\n' ' ')

    if [[ "$jobs" == "" ]]; then
        return 0
    fi

    # Delete pod
    k delete jobs.batch -n $namespace $(echo $jobs)
}

function enable-cluster-access() {
    cred=$(tanzu account cred list | fzf | awk '{print $1}')
    arn=$(tanzu account cred get $cred -o json | jq '.spec.data.awsCredential.iamRole.arn' -r)

    #echo "Paste the following into the file opened for editing, with the role of the credential you would like to adopt with"

    kubectl create clusterrolebinding adoption-cluster-role-binding \
        --clusterrole=cluster-admin \
        --group=adoption
    
    # Set relevant string values
    groupString="- groups:\n  - adoption\n  rolearn: $arn\n"
    mapRoles="$(k get -n kube-system configmap/aws-auth -o json | jq --arg new $groupString '.data.mapRoles + $new' | sed 's/\\\\/\\/g' | jq -r)"
    configMap="$(k get -n kube-system configmap/aws-auth -o json | jq --arg new $mapRoles '.data.mapRoles = $new')"

    # write to file and replace strings
    echo "Writing to configmap:"
    echo $configMap | tee aws-auth-config-map.json
    k replace -n kube-system configmap/aws-auth -f aws-auth-config-map.json
}

function get-eks-kubeconfig() {
    cluster=$(tanzu ekscluster list | fzf)
    name=$(echo $cluster | awk '{print $1}')
    cred=$(echo $cluster | awk '{print $2}')
    region=$(echo $cluster | awk '{print $3}')
    agent_name=$(tanzu ekscluster get $name --region $region --credential-name $cred | grep agentName | awk '{print $2}')

    tanzu mission-control cluster kubeconfig get $agent_name -p eks -m eks > ~/.kube/$agent_name
}

function refresh-ucp-kubeconfig() {
    token
    
    echo "apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZPakNDQkNLZ0F3SUJBZ0lTQkZld3didVByaGJUZ09JRWozZ1B1T0FDTUEwR0NTcUdTSWIzRFFFQkN3VUEKTURJeEN6QUpCZ05WQkFZVEFsVlRNUll3RkFZRFZRUUtFdzFNWlhRbmN5QkZibU55ZVhCME1Rc3dDUVlEVlFRRApFd0pTTXpBZUZ3MHlNekE1TWpVeE9UUTNNVE5hRncweU16RXlNalF4T1RRM01USmFNRUV4UHpBOUJnTlZCQU1UCk5uVmpjQzFxYUdWeWNtbHNaQzB5TG5OMFlXTnJjeTVpYkhWbGMydDVMblJ0WXkxa1pYWXVZMnh2ZFdRdWRtMTMKWVhKbExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOa284S0NHeG04RAoyN3g0Sk5lMEduZzJNM1dLOE9sZmNWY2g0aUlOdGlmTmh0djRXRnBFM1RBN0dkc2lhdlJvdFdVaWw5Zm9hdDRlCnlEalpjY2llMko5UUttRzhLMElPUFhqSjZBOC91OFEzQVZrUzNySmZ5RVROYWcrUGc2ZVdkSHM0MlhpYk4ra0cKV25FNk8wU2t5b0crdTA3QkNlTVZpaHZPRG9YT2p5RTl3N2FXR21INEN0VitqZVcwVU1IdW9seFlmZmFBVHliYwpzZkpreFplOEhpc2lydy9oQ3JXUjNMYUQ1QmpnckdrOVNuVEdNUGZoQWZ5cmVTYWcrbjJHaHdMYlQ5SEhlSnhYClJMdWhwdk9KcVJTUm9ZZjlCaU5hekJESEozdnl2b1VlUGFXNWl1cXBVaENidXF3c0Q3LzlQZGM4NmxPdysrRGkKL1FGM1JkZkNpbThDQXdFQUFhT0NBamt3Z2dJMU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVQpCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVUzN2xjCm9pM0Z3OE5pNU9kWkowV0NYUVhSbThZd0h3WURWUjBqQkJnd0ZvQVVGQzZ6RjdkWVZzdXVVQWxBNWgrdm5Zc1UKd3NZd1ZRWUlLd1lCQlFVSEFRRUVTVEJITUNFR0NDc0dBUVVGQnpBQmhoVm9kSFJ3T2k4dmNqTXVieTVzWlc1agpjaTV2Y21jd0lnWUlLd1lCQlFVSE1BS0dGbWgwZEhBNkx5OXlNeTVwTG14bGJtTnlMbTl5Wnk4d1FRWURWUjBSCkJEb3dPSUkyZFdOd0xXcG9aWEp5YVd4a0xUSXVjM1JoWTJ0ekxtSnNkV1Z6YTNrdWRHMWpMV1JsZGk1amJHOTEKWkM1MmJYZGhjbVV1WTI5dE1CTUdBMVVkSUFRTU1Bb3dDQVlHWjRFTUFRSUJNSUlCQlFZS0t3WUJCQUhXZVFJRQpBZ1NCOWdTQjh3RHhBSGNBdHo3N0pOK2NUYnAxOGpuRnVsajBiRjM4UXM5Nm56WEVuaDBKZ1NYdHRKa0FBQUdLCnpoaVphd0FBQkFNQVNEQkdBaUVBdE1mZjQwdHFmSXAyT2FDM0NES01mTjdRaHRlTndXUUVTQmgyQ1FBUkcyb0MKSVFEMkhyU0FrbUh3V0NIbEJHZlVWQnVCUXArU0M3bDdxeGxFUzd0eXNoR0t3d0IyQUhveWpGVFl0eTIySU9vNAo0RkllNllRV2NESVRoVTA3MGl2Qk9sZWpVdXRTQUFBQmlzNFltNUlBQUFRREFFY3dSUUlnR0JORlQ1eStTUmk2CkFoOGpJbmFERFZ5U3VodENUeG9zbDhOUXhJQTYxcUFDSVFDaS9XMy9QbVFOZGJOWlBaV1UzZXp0NFVWc05vc2wKMTM5Z05GaDQ1NldxMWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXJNWHV5ZElSWmpuWnlDbjA4VTE1WDZsQwpweVpiWm9iMmtEVUhOQ0VmZGtBTzhuSGUrbUJaYVJ0T2wxSmZPZ1k3eXJYQXlwczhLRi9sOFdTa3ZteTY0a3lhCktvQ0NUUGJlTFhrREYyQUpsT0NjZFlYendtOWFHMHYxZmhnWnZZckN2cmlJYmI0eWwxeXc2L3pMSlBjTXZObVkKS0RpajhpYStNVGxCT2FHOFp6MWZTZnhFM3E3eHFCMmZKVC90bWNuSUlsejlEZVFJNTZHREZzU1VBbjlidDcyaworYmJhZnBoc21CbHhETnNzbGJxdzlkaW5aQ1lReDNManNtT2RCSVBrUHpYWTYwQ2VBalBoTVA2MnNwTDNZRGJKClpsdVJKdFpOcEJUMGZkTHdwTExTbTJGTzRRdGxPUUxpVC9TQnc3Y0V3NDdtUTRDaWx2d1NRTFEycDc5d253PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQoK
    server: https://ucp-jherrild-2.stacks.bluesky.tmc-dev.cloud.vmware.com/org/bc27608b-4809-4cac-9e04-778803963da2
  name: org
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZPakNDQkNLZ0F3SUJBZ0lTQkZld3didVByaGJUZ09JRWozZ1B1T0FDTUEwR0NTcUdTSWIzRFFFQkN3VUEKTURJeEN6QUpCZ05WQkFZVEFsVlRNUll3RkFZRFZRUUtFdzFNWlhRbmN5QkZibU55ZVhCME1Rc3dDUVlEVlFRRApFd0pTTXpBZUZ3MHlNekE1TWpVeE9UUTNNVE5hRncweU16RXlNalF4T1RRM01USmFNRUV4UHpBOUJnTlZCQU1UCk5uVmpjQzFxYUdWeWNtbHNaQzB5TG5OMFlXTnJjeTVpYkhWbGMydDVMblJ0WXkxa1pYWXVZMnh2ZFdRdWRtMTMKWVhKbExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOa284S0NHeG04RAoyN3g0Sk5lMEduZzJNM1dLOE9sZmNWY2g0aUlOdGlmTmh0djRXRnBFM1RBN0dkc2lhdlJvdFdVaWw5Zm9hdDRlCnlEalpjY2llMko5UUttRzhLMElPUFhqSjZBOC91OFEzQVZrUzNySmZ5RVROYWcrUGc2ZVdkSHM0MlhpYk4ra0cKV25FNk8wU2t5b0crdTA3QkNlTVZpaHZPRG9YT2p5RTl3N2FXR21INEN0VitqZVcwVU1IdW9seFlmZmFBVHliYwpzZkpreFplOEhpc2lydy9oQ3JXUjNMYUQ1QmpnckdrOVNuVEdNUGZoQWZ5cmVTYWcrbjJHaHdMYlQ5SEhlSnhYClJMdWhwdk9KcVJTUm9ZZjlCaU5hekJESEozdnl2b1VlUGFXNWl1cXBVaENidXF3c0Q3LzlQZGM4NmxPdysrRGkKL1FGM1JkZkNpbThDQXdFQUFhT0NBamt3Z2dJMU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVQpCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVUzN2xjCm9pM0Z3OE5pNU9kWkowV0NYUVhSbThZd0h3WURWUjBqQkJnd0ZvQVVGQzZ6RjdkWVZzdXVVQWxBNWgrdm5Zc1UKd3NZd1ZRWUlLd1lCQlFVSEFRRUVTVEJITUNFR0NDc0dBUVVGQnpBQmhoVm9kSFJ3T2k4dmNqTXVieTVzWlc1agpjaTV2Y21jd0lnWUlLd1lCQlFVSE1BS0dGbWgwZEhBNkx5OXlNeTVwTG14bGJtTnlMbTl5Wnk4d1FRWURWUjBSCkJEb3dPSUkyZFdOd0xXcG9aWEp5YVd4a0xUSXVjM1JoWTJ0ekxtSnNkV1Z6YTNrdWRHMWpMV1JsZGk1amJHOTEKWkM1MmJYZGhjbVV1WTI5dE1CTUdBMVVkSUFRTU1Bb3dDQVlHWjRFTUFRSUJNSUlCQlFZS0t3WUJCQUhXZVFJRQpBZ1NCOWdTQjh3RHhBSGNBdHo3N0pOK2NUYnAxOGpuRnVsajBiRjM4UXM5Nm56WEVuaDBKZ1NYdHRKa0FBQUdLCnpoaVphd0FBQkFNQVNEQkdBaUVBdE1mZjQwdHFmSXAyT2FDM0NES01mTjdRaHRlTndXUUVTQmgyQ1FBUkcyb0MKSVFEMkhyU0FrbUh3V0NIbEJHZlVWQnVCUXArU0M3bDdxeGxFUzd0eXNoR0t3d0IyQUhveWpGVFl0eTIySU9vNAo0RkllNllRV2NESVRoVTA3MGl2Qk9sZWpVdXRTQUFBQmlzNFltNUlBQUFRREFFY3dSUUlnR0JORlQ1eStTUmk2CkFoOGpJbmFERFZ5U3VodENUeG9zbDhOUXhJQTYxcUFDSVFDaS9XMy9QbVFOZGJOWlBaV1UzZXp0NFVWc05vc2wKMTM5Z05GaDQ1NldxMWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXJNWHV5ZElSWmpuWnlDbjA4VTE1WDZsQwpweVpiWm9iMmtEVUhOQ0VmZGtBTzhuSGUrbUJaYVJ0T2wxSmZPZ1k3eXJYQXlwczhLRi9sOFdTa3ZteTY0a3lhCktvQ0NUUGJlTFhrREYyQUpsT0NjZFlYendtOWFHMHYxZmhnWnZZckN2cmlJYmI0eWwxeXc2L3pMSlBjTXZObVkKS0RpajhpYStNVGxCT2FHOFp6MWZTZnhFM3E3eHFCMmZKVC90bWNuSUlsejlEZVFJNTZHREZzU1VBbjlidDcyaworYmJhZnBoc21CbHhETnNzbGJxdzlkaW5aQ1lReDNManNtT2RCSVBrUHpYWTYwQ2VBalBoTVA2MnNwTDNZRGJKClpsdVJKdFpOcEJUMGZkTHdwTExTbTJGTzRRdGxPUUxpVC9TQnc3Y0V3NDdtUTRDaWx2d1NRTFEycDc5d253PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQoK
    server: https://ucp-jherrild-2.stacks.bluesky.tmc-dev.cloud.vmware.com/org/bc27608b-4809-4cac-9e04-778803963da2/project/project-hr
  name: project
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZPakNDQkNLZ0F3SUJBZ0lTQkZld3didVByaGJUZ09JRWozZ1B1T0FDTUEwR0NTcUdTSWIzRFFFQkN3VUEKTURJeEN6QUpCZ05WQkFZVEFsVlRNUll3RkFZRFZRUUtFdzFNWlhRbmN5QkZibU55ZVhCME1Rc3dDUVlEVlFRRApFd0pTTXpBZUZ3MHlNekE1TWpVeE9UUTNNVE5hRncweU16RXlNalF4T1RRM01USmFNRUV4UHpBOUJnTlZCQU1UCk5uVmpjQzFxYUdWeWNtbHNaQzB5TG5OMFlXTnJjeTVpYkhWbGMydDVMblJ0WXkxa1pYWXVZMnh2ZFdRdWRtMTMKWVhKbExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOa284S0NHeG04RAoyN3g0Sk5lMEduZzJNM1dLOE9sZmNWY2g0aUlOdGlmTmh0djRXRnBFM1RBN0dkc2lhdlJvdFdVaWw5Zm9hdDRlCnlEalpjY2llMko5UUttRzhLMElPUFhqSjZBOC91OFEzQVZrUzNySmZ5RVROYWcrUGc2ZVdkSHM0MlhpYk4ra0cKV25FNk8wU2t5b0crdTA3QkNlTVZpaHZPRG9YT2p5RTl3N2FXR21INEN0VitqZVcwVU1IdW9seFlmZmFBVHliYwpzZkpreFplOEhpc2lydy9oQ3JXUjNMYUQ1QmpnckdrOVNuVEdNUGZoQWZ5cmVTYWcrbjJHaHdMYlQ5SEhlSnhYClJMdWhwdk9KcVJTUm9ZZjlCaU5hekJESEozdnl2b1VlUGFXNWl1cXBVaENidXF3c0Q3LzlQZGM4NmxPdysrRGkKL1FGM1JkZkNpbThDQXdFQUFhT0NBamt3Z2dJMU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVQpCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVUzN2xjCm9pM0Z3OE5pNU9kWkowV0NYUVhSbThZd0h3WURWUjBqQkJnd0ZvQVVGQzZ6RjdkWVZzdXVVQWxBNWgrdm5Zc1UKd3NZd1ZRWUlLd1lCQlFVSEFRRUVTVEJITUNFR0NDc0dBUVVGQnpBQmhoVm9kSFJ3T2k4dmNqTXVieTVzWlc1agpjaTV2Y21jd0lnWUlLd1lCQlFVSE1BS0dGbWgwZEhBNkx5OXlNeTVwTG14bGJtTnlMbTl5Wnk4d1FRWURWUjBSCkJEb3dPSUkyZFdOd0xXcG9aWEp5YVd4a0xUSXVjM1JoWTJ0ekxtSnNkV1Z6YTNrdWRHMWpMV1JsZGk1amJHOTEKWkM1MmJYZGhjbVV1WTI5dE1CTUdBMVVkSUFRTU1Bb3dDQVlHWjRFTUFRSUJNSUlCQlFZS0t3WUJCQUhXZVFJRQpBZ1NCOWdTQjh3RHhBSGNBdHo3N0pOK2NUYnAxOGpuRnVsajBiRjM4UXM5Nm56WEVuaDBKZ1NYdHRKa0FBQUdLCnpoaVphd0FBQkFNQVNEQkdBaUVBdE1mZjQwdHFmSXAyT2FDM0NES01mTjdRaHRlTndXUUVTQmgyQ1FBUkcyb0MKSVFEMkhyU0FrbUh3V0NIbEJHZlVWQnVCUXArU0M3bDdxeGxFUzd0eXNoR0t3d0IyQUhveWpGVFl0eTIySU9vNAo0RkllNllRV2NESVRoVTA3MGl2Qk9sZWpVdXRTQUFBQmlzNFltNUlBQUFRREFFY3dSUUlnR0JORlQ1eStTUmk2CkFoOGpJbmFERFZ5U3VodENUeG9zbDhOUXhJQTYxcUFDSVFDaS9XMy9QbVFOZGJOWlBaV1UzZXp0NFVWc05vc2wKMTM5Z05GaDQ1NldxMWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXJNWHV5ZElSWmpuWnlDbjA4VTE1WDZsQwpweVpiWm9iMmtEVUhOQ0VmZGtBTzhuSGUrbUJaYVJ0T2wxSmZPZ1k3eXJYQXlwczhLRi9sOFdTa3ZteTY0a3lhCktvQ0NUUGJlTFhrREYyQUpsT0NjZFlYendtOWFHMHYxZmhnWnZZckN2cmlJYmI0eWwxeXc2L3pMSlBjTXZObVkKS0RpajhpYStNVGxCT2FHOFp6MWZTZnhFM3E3eHFCMmZKVC90bWNuSUlsejlEZVFJNTZHREZzU1VBbjlidDcyaworYmJhZnBoc21CbHhETnNzbGJxdzlkaW5aQ1lReDNManNtT2RCSVBrUHpYWTYwQ2VBalBoTVA2MnNwTDNZRGJKClpsdVJKdFpOcEJUMGZkTHdwTExTbTJGTzRRdGxPUUxpVC9TQnc3Y0V3NDdtUTRDaWx2d1NRTFEycDc5d253PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQoK
    server: https://ucp-jherrild-2.stacks.bluesky.tmc-dev.cloud.vmware.com/org/bc27608b-4809-4cac-9e04-778803963da2/project/project-hr/space/space-a
  name: project-space-a
contexts:
- context:
    cluster: org
    user: ucp-user
  name: org
- context:
    cluster: project
    user: ucp-user
  name: project
- context:
    cluster: project-space-a
    user: ucp-user
  name: project-space-a
current-context: org
kind: Config
preferences: {}
users:
- name: ucp-user
  user:
    token: $ACCESS_TOKEN" > $HOME/.kube/ucp-jherrild-2 
}

tar-from-url() {
    URL="$1"
    curl -OL "$URL"
    tar -xvf "${URL##*/}"
    rm "${URL##*/}"
}

# Checks out a new branch from the repo with the help of fzf 
switch() {
    branch=$(git branch | fzf)
    git checkout $(echo "$branch" | tr -d '*')
}