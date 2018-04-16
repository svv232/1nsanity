#!/bin/bash
NORMAL=$(gcc test.c && ./a.out)
OBFUSCATE=$(./test)
DEBUG=1;

function debug {
    echo $NORMAL;
    echo $OBFUSCATE;
}

function check {
    if [ $NORMAL==$OBFUSCATE ]
    then
        echo OUTPUTS ARE EQUAL!;
    fi
}

function clean {
    if [ $DEBUG ]
    then
        debug;
    fi
    rm a.out;
}

clean;
check;
