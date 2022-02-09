unsetopt PROMPT_SP
PS1=''

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

COMMON_FG_1='blue'
COMMON_FG_2='white'
COMMON_BG='light-black'

export ALIEN_KEEP_PROMPT=1
export ALIEN_PROMPT_SYM='❯'
export ALIEN_USE_NERD_FONT=1
export ALIEN_SECTIONS_LEFT_SEP_SYM=' '
export ALIEN_SECTIONS_RIGHT_SEP_SYM=' '
export ALIEN_SECTION_TIME_FORMAT='%H:%M:%S'
export ALIEN_THEME='soft'
# export ALIEN_VERSIONS_PROMPT='JAVA_S'

export ALIEN_PROMPT_FG=$COMMON_FG_1
export ALIEN_SECTION_EXIT_FG=$COMMON_BG
export ALIEN_SECTION_EXIT_BG=$COMMON_FG_1
export ALIEN_SECTION_EXIT_BG_ERROR='red'
export ALIEN_SECTION_TIME_FG=$COMMON_FG_2
export ALIEN_SECTION_TIME_BG=$COMMON_BG
export ALIEN_SECTION_BATTERY_FG=$COMMON_FG_1
export ALIEN_SECTION_BATTERY_BG=$COMMON_BG
export ALIEN_SECTION_USER_FG=$COMMON_FG_1
export ALIEN_SECTION_USER_BG=$COMMON_BG
export ALIEN_SECTION_PATH_FG=$COMMON_FG_1
export ALIEN_SECTION_PATH_BG=$COMMON_BG
export ALIEN_SECTION_VCS_BRANCH_FG=$COMMON_FG_2
export ALIEN_SECTION_VCS_BRANCH_BG=$COMMON_BG
export ALIEN_SECTION_VCS_STATUS_FG=$COMMON_FG_2
export ALIEN_SECTION_VCS_STATUS_BG=$COMMON_BG
export ALIEN_SECTION_VCS_DIRTY_FG=$COMMON_FG_2
export ALIEN_SECTION_VCS_DIRTY_BG=$COMMON_BG
export ALIEN_SECTION_SSH_FG=$COMMON_FG_2
export ALIEN_SECTION_VENV_FG=$COMMON_FG_2
export ALIEN_GIT_TRACKED_COLOR='green'
export ALIEN_GIT_UN_TRACKED_COLOR='red'
export ALIEN_SECTION_VERSION_BG=$COMMON_BG

export KUBE_PS1_PREFIX=''
export KUBE_PS1_SUFFIX=''
export KUBE_PS1_SEPARATOR=' '
export KUBE_PS1_SYMBOL_DEFAULT='\ufd31'
export KUBE_PS1_CTX_COLOR=$COMMON_FG_1
export KUBE_PS1_NS_COLOR=$COMMON_FG_1

alien_prompt_section_aws_status() {
    time_left=$($HOME/.aws/bin/aws-time-left)
    foreground='green'

    if (($time_left <= 0)); then
        time_left='0'
        foreground='red'
    fi

    __section=(
        content "\uf52c ${time_left}m"
        foreground $foreground
        separator 1
    )
}

alien_prompt_section_k8s_status() {
    __section=(
        content "$(kube_ps1)"
        separator 1
    )
}

alien_prompt_section_java_version() {
    JAVA_HOME=$(asdf where java)
    eval $(cat $JAVA_HOME/release | grep JAVA_VERSION=)

    __section=(
        content "\ue256 $JAVA_VERSION"
        foreground 'grey'
        separator 1
    )
}

alien_prompt_section_go_version() {
    eval GO_VERSION=$(go version | cut -d " " -f 3 | cut -d "o" -f 2)

    __section=(
        content "\ufcd1 $GO_VERSION"
        foreground 'grey'
        separator 1
    )
}

alien_prompt_section_error_sensitive_prompt() {
    __section=(
        content " ${ALIEN_PROMPT_SYM} "
        foreground "%(?.$ALIEN_SECTION_EXIT_BG.$ALIEN_SECTION_EXIT_BG_ERROR)"
    )
}

function preexec() {
    timer=$(($(print -P %D{%s%6.})/1000))
}

function kill_timer() {
    unset timer
}

add-zsh-hook precmd kill_timer

# Relies on preexec()
alien_prompt_section_timer() {
    if (( timer )); then
        now=$(($(print -P %D{%s%6.})/1000))
        elapsed=$(($now-$timer))

        LAST_CMD_TIME="\ufa1a ${elapsed}ms"
        unset $timer
    else
        LAST_CMD_TIME="\ufa1d"
    fi

    __section=(
        content $LAST_CMD_TIME
        foreground $ALIEN_SECTION_TIME_FG
        background $ALIEN_SECTION_TIME_BG
        separator 1
    )
}

alien_prompt_section_kube_config() {
    color='blue'
    kube=$(basename $KUBECONFIG | cut -d '-' -f1)
    config=$(basename $KUBECONFIG | cut -d '-' -f4)

    if [[ $kube == "" ]]; then
        color='red'
        output="NONE"
    else
        output=$kube-$config
    fi
    
    __section=(
        content "\ue79b $output"
        foreground $color
        separator 1
    )
}

alien_prompt_section_stack_status() {
    stacks=$(kubectl get stacks | fzf -e -f $(whoami))
    pattern="Ready"
    output=""

    echo $stacks | while read stack; do
        stack_string=$(echo $stack | awk '{print $4,$6}' | tr ' ' ':' | tr '\n' ' ')
        if [[ $stack_string == *$pattern* ]]; then
            output+="%F{green}\ue257 $stack_string%f";
        else
            output+="%F{red}\ue257 $stack_string%f";
        fi
    done

    __section+=(
        content "$output"
        separator 1
    )
}

export ALIEN_SECTIONS_RIGHT=(
    time:async
    timer:async
    vcs_branch:async
    vcs_status:async
    vcs_dirty:async
    # java_version:async
    # go_version:async
    #versions:async
    # aws_status:async
    # k8s_status:async
    kube_config:async
    stack_status:async
)

export ALIEN_SECTIONS_LEFT=(
    # exit
    # battery
    # user
    path:async
    newline
    # ssh
    # venv
    # prompt
    error_sensitive_prompt
)

zinit ice wait lucid atload'precmd'; zinit light eendroroy/alien
