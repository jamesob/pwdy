#!/bin/bash

function _pwdycomplete()
{
    local cmd="${1##*/}"
    local word=${COMP_WORDS[COMP_CWORD]}
    local line=${COMP_LINE}

    COMPREPLY=($(compgen -W "%s" ${word}))
}

complete -F _pwdycomplete pwdy
