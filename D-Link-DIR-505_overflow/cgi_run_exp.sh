#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh

python generate.py
INPUT=`python -c "print open('payload','r').read()"`

LEN=$(echo $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mips-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu  -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="maultipart/formdata" -E SCRIPT_NAME="common"  -E REQUEST_METHOD="POST"  -E REQUEST_URI="/my_cgi.cgi" -E REMOTE_ADDR="192.168.1.1" -g $PORT /usr/bin/my_cgi.cgi 2>/dev/null
echo "run ok"
rm -f ./qemu

