#!/bin/bash
FT_NM="../ft_nm"
NM="/usr/bin/nm"
DIFF="/usr/bin/diff"
GCC64="/usr/bin/gcc"
GCC32="/usr/bin/gcc -m32"

mkdir -p tmp/

function test() {
    sed "s| ET_NONE;| $3;|g" elf_builder.c > ./tmp/tmp.c
    $2 ./tmp/tmp.c -o ./tmp/tmp.bin
    ./tmp/tmp.bin > ./tmp/"$1".bin
    "$NM"       ./tmp/"$1".bin > ./tmp/"$1".nm 2>/dev/null
    "$FT_NM"    ./tmp/"$1".bin > ./tmp/"$1".ft 2>/dev/null
    "$DIFF"     ./tmp/"$1".nm ./tmp/"$1".ft > ./tmp/"$1".diff
    if [ $? != "0" ]; then
        printf '%s \e[91mFAILED\e[0m (./tmp/%s.diff)\n' "$1" "$1"
    else
        printf '%s \e[92mSUCCESS\e[0m\n' "$1"
    fi
}

test "64-ET_NONE"   "$GCC64" "ET_NONE"
test "64-ET_REL"    "$GCC64" "ET_REL"
test "64-ET_EXEC"   "$GCC64" "ET_EXEC"
test "64-ET_DYN"    "$GCC64" "ET_DYN"
test "64-ET_CORE"   "$GCC64" "ET_CORE"

test "32-ET_NONE"   "$GCC32" "ET_NONE"
test "32-ET_REL"    "$GCC32" "ET_REL"
test "32-ET_EXEC"   "$GCC32" "ET_EXEC"
test "32-ET_DYN"    "$GCC32" "ET_DYN"
test "32-ET_CORE"   "$GCC32" "ET_CORE"
