# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Huawei Device Co., Ltd.

set -e
# 定义信号处理函数
cleanup() {
    echo "test result fail, exit"
    exit
}

echo "start test"
function 0100() {
    rm -rf /data/lgs0100
    mkdir -p /data/lgs0100
    mkdir -p /data/mntlgs0100

    touch /data/lgs0100/test.txt

    mount -t sharefs /data/lgs0100 /data/mntlgs0100 -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd set --tokenid 0100 --path "/data/mntlgs0100" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0100 --path "/data/mntlgs0100" --mode 2 --expect true
	
	./dectool --cmd destroy --tokenid 0100 --expect true
	
    umount /data/mntlgs0100 -l
}

function 0200() {
    rm -rf /data/lgs0200
    mkdir -p /data/lgs0200
    mkdir -p /data/mntlgs0200

    touch /data/lgs0200/test.txt

    mount -t sharefs /data/lgs0200 /data/mntlgs0200 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs0200"

    ./dectool --cmd set --tokenid 0200 --path "/data/mntlgs0200" --mode 1 --persist true --expect true
    ./dectool --cmd set --tokenid 0200 --path "/data/mntlgs0200" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0200 --path "/data/mntlgs0200" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0200 --expect true
	
    umount /data/mntlgs0200 -l
}

function 0300() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs0300

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs0300 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs0300"

    ./dectool --cmd set --tokenid 0300 --path "/data/mntlgs1300" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0300 --path "/data/mntlgs0300" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0300 --expect true
    
    umount /data/mntlgs0300 -l
}

function 0400() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs0400

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs0400 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs0400"

    /data/dectool --cmd set --tokenid 0 --path "/data/mntlgs0400" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0 --path "/data/mntlgs0400" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0 --expect true
	
    umount /data/mntlgs0400 -l
	
}

function 0600() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs0600

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs0600 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs0600"

    ./dectool --cmd set --tokenid 0600 --path "/data/mntlgs0600" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0600 --path "/data/mntlgs0600" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 0600 --path "/data/mntlgs0600" --expect true

    ./dectool --cmd check --tokenid 0600 --path "/data/mntlgs0600" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 0600 --path "/data/mntlgs0600" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0600 --expect true
	
    umount /data/mntlgs0600 -l
}

function 0700() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 0700 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 0700 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd delete --tokenid 0700 --path "/data/mntlgs1" --expect false
    ./dectool --cmd check --tokenid 0700 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd set --tokenid 0700 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 0700 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd delete --tokenid 07001 --path "/data/mntlgs" --expect false
    ./dectool --cmd check --tokenid 0700 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 0700 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0700 --expect true
	./dectool --cmd destroy --tokenid 07001 --expect true
    
    umount /data/mntlgs -l
}

function 0800() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 0800 --path "/data/mntlgs" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0800 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd set --tokenid 0800 --path "/data/mntlgs" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 0800 --path "/data/mntlgs" --mode 1 --expect true
    ./dectool --cmd check --tokenid 0800 --path "/data/mntlgs" --mode 2 --expect true
    ./dectool --cmd check --tokenid 0800 --path "/data/mntlgs" --mode 3 --expect true
	
	./dectool --cmd destroy --tokenid 0800 --expect true
    
    umount /data/mntlgs -l
}

function 0900() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
    mkdir -p /data/mntlgs1

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 0900 --path "/data/mntlgs" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 0900 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd set --tokenid 0900 --path "/data/mntlgs" --mode 0 --persist true --expect true
	./dectool --cmd set --tokenid 09001 --path "/data/mntlgs" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 0900 --path "/data/mntlgs1" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 0900 --path "/data/mntlgs" --mode 1 --expect true
    ./dectool --cmd check --tokenid 0900 --path "/data/mntlgs" --mode 2 --expect false
    ./dectool --cmd check --tokenid 0900 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 0900 --expect true
	./dectool --cmd destroy --tokenid 09001 --expect true
    
    umount /data/mntlgs -l
}

function 1000() {
    rm -rf /data/lgs1000
    mkdir -p /data/lgs1000
    mkdir -p /data/mntlgs10
    mkdir -p /data/mntlgs1000

    touch /data/lgs1000/test.txt

    mount -t sharefs /data/lgs1000 /data/mntlgs10 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs10"

    ./dectool --cmd set --tokenid 1000 --path "/data/mntlgs10" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 1000 --path "/data/mntlgs10" --mode 1 --expect true
	./dectool --cmd query --tokenid 1000 --path "/data/mntlgs10" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 10000 --path "/data/mntlgs10" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1000 --path "/data/mntlgs10" --mode 2 --expect false
	
	./dectool --cmd check --tokenid 1000 --path "/data/mntlgs1000" --mode 1 --expect true
	
    ./dectool --cmd query --tokenid 10000 --path "/data/mntlgs10" --mode 1 --expect false
    
	./dectool --cmd query --tokenid 1000 --path "/data/mntlgs10" --mode 2 --expect false
	
	./dectool --cmd query --tokenid 1000 --path "/data/mntlgs1000" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1000 --path "/data/mntlgs10" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1000 --expect true
	
    umount /data/mntlgs10 -l
}

function 1100() {
    rm -rf /data/lgs1100
    mkdir -p /data/mntlgs110000
    mkdir -p /data/mntlgs11
    mkdir -p /data/mntlgs1100
	mkdir -p /data/lgs1100

    touch /data/lgs1100/test.txt

    mount -t sharefs /data/lgs1100 /data/mntlgs11 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs11"

    ./dectool --cmd set --tokenid 1100 --path "/data/mntlgs11" --mode 1 --expect true
	./dectool --cmd check --tokenid 1100 --path "/data/mntlgs11" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 11000 --path "/data/mntlgs11" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1100 --path "/data/mntlgs11" --mode 2 --expect false
	
	./dectool --cmd check --tokenid 1100 --path "/data/mntlgs110000" --mode 1 --expect true
	
	./dectool --cmd query --tokenid 1100 --path "/data/mntlgs11" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1100 --path "/data/mntlgs11" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1100 --expect true
	
    umount /data/mntlgs11 -l
	rm -rf /data/mntlgs110000
}

function 1200() {
    rm -rf /data/lgs1200
    mkdir -p /data/lgs1200
    mkdir -p /data/mntlgs12
    mkdir -p /data/mntlgs1200

    touch /data/lgs1200/test.txt

    mount -t sharefs /data/lgs1200 /data/mntlgs12 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs12"

    ./dectool --cmd set --tokenid 1200 --path "/data/mntlgs12" --mode 1 --expect true
	./dectool --cmd set --tokenid 1200 --path "/data/mntlgs12" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 1200 --path "/data/mntlgs12" --mode 1 --expect true
	./dectool --cmd query --tokenid 1200 --path "/data/mntlgs12" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 12001 --path "/data/mntlgs12" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1200 --path "/data/mntlgs12" --mode 2 --expect false
	
	./dectool --cmd check --tokenid 1200 --path "/data/mntlgs1200" --mode 1 --expect true
	
    ./dectool --cmd query --tokenid 12001 --path "/data/mntlgs12" --mode 1 --expect false
    
	./dectool --cmd query --tokenid 1200 --path "/data/mntlgs12" --mode 2 --expect false
	
	./dectool --cmd query --tokenid 1200 --path "/data/mntlgs1200" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1200 --path "/data/mntlgs12" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1200 --expect true
	
    umount /data/mntlgs12 -l
}

function 1300() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 1300 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 1300 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd query --tokenid 1300 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1300 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1300 --expect true
	
    umount /data/mntlgs -l
}

function 1400() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 1400 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd check --tokenid 1400 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1400 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1400 --expect true
	
    umount /data/mntlgs -l
}

function 1500() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 1500 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd set --tokenid 1500 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 1500 --path "/data/mntlgs" --mode 1 --expect true
	./dectool --cmd query --tokenid 1500 --path "/data/mntlgs" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1500 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 1500 --expect true
	
    umount /data/mntlgs -l
}

function 1600()
{
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/lgs/dir1/dir11
    mkdir -p /data/lgs/dir1/
    mkdir -p /data/mntlgspaths1600

    touch /data/lgs/test.txt
    touch "/data/lgs/*"
    touch "/data/lgs/dir1/test2.txt"

    cd /data
    mount -t sharefs /data/lgs /data/mntlgspaths1600 -o override_support_delete -o user_id=100

    ./dectool --cmd constraint --path "/data/mntlgspaths1600/"

    ./dectool --cmd set --tokenid 1600 --path "/data/mntlgspaths1600/*" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 1600 --path "/data/mntlgspaths1600/dir1/" --expect false

    ./dectool --cmd check --tokenid 1600 --path "/data/mntlgspaths1600/*" --expect true

    ./dectool --cmd readdir --tokenid 1600 --path "/data/mntlgspaths1600/dir1/" --expect false
    ./dectool --cmd read --tokenid 1600 --path "/data/mntlgspaths1600/test.txt" --expect false
    ./dectool --cmd read --tokenid 1600 --path "/data/mntlgspaths1600/dir1/test.txt" --expect false

    ./dectool --cmd read --tokenid 1600 --path "/data/mntlgspaths1600/*" --expect true

    umount /data/mntlgspaths1600 -l
}

function 1700() {
    rm -rf /data/lgs1700
    mkdir -p /data/lgs1700
    mkdir -p /data/mntlgs17
    mkdir -p /data/mntlgs1700

    touch /data/lgs1700/test.txt

    mount -t sharefs /data/lgs1700 /data/mntlgs17 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs17"
	./dectool --cmd constraint --path "/data/mntlgs1700"

    ./dectool --cmd set --tokenid 1700 --path "/data/mntlgs17" --mode 1 --expect true
	./dectool --cmd set --tokenid 1700 --path "/data/mntlgs1700" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1700 --path "/data/mntlgs17001" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs17" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs1700/1" --mode 1 --expect true
	./dectool --cmd query --tokenid 1700 --path "/data/mntlgs1700" --mode 1 --expect true
	
	./dectool --cmd destroy --tokenid 1700 --expect true
	
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs17" --mode 1 --expect false
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs17" --mode 2 --expect false
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs17" --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs1700" --mode 1 --expect false
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs1700/1" --mode 1 --expect false
	./dectool --cmd query --tokenid 1700 --path "/data/mntlgs1700" --mode 1 --expect false
	./dectool --cmd query --tokenid 1700 --path "/data/mntlgs1700" --mode 2 --expect false
	./dectool --cmd query --tokenid 1700 --path "/data/mntlgs1700" --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1700 --path "/data/mntlgs17001" --mode 1 --expect true
	./dectool --cmd query --tokenid 1700 --path "/data/mntlgs17001" --mode 3 --expect true
	
	./dectool --cmd destroy --tokenid 1700 --expect true
	
    umount /data/mntlgs17 -l
}

function 1800() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/*/"

    ./dectool --cmd set --tokenid 1800 --path "/data/*/" --mode 1 --persist true --expect true
    ./dectool --cmd set --tokenid 1800 --path "/data/*/A/*" --mode 1 --persist true --expect true
    ./dectool --cmd set --tokenid 1800 --path "/data/*/A/*/*" --mode 1 --persist true --expect true
    ./dectool --cmd set --tokenid 1800 --path "/data/*/A/*/B" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 1800 --path "/data/A/A" --mode 1 --expect true
	./dectool --cmd check --tokenid 1800 --path "/data/1/A/8" --mode 1 --expect true
	./dectool --cmd check --tokenid 1800 --path "/data/@/A/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1800 --path "/data/*/B" --mode 1 --expect true
	./dectool --cmd check --tokenid 1800 --path "/data/*/A/*" --mode 1 --expect true
	./dectool --cmd check --tokenid 1800 --path "/data/*/A/*/B" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1800 --path "/data/A" --mode 3 --expect true
	
	./dectool --cmd query --tokenid 1800 --path "/data/p/A/A" --mode 1 --expect true
	./dectool --cmd query --tokenid 1800 --path "/data/2/3" --mode 1 --expect true
	./dectool --cmd query --tokenid 1800 --path "/data/HHHHHHH/YYYYYY" --mode 1 --expect true
	./dectool --cmd query --tokenid 1800 --path "/data/*/B" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1800 --path "/data/*/" --expect true
	
	./dectool --cmd destroy --tokenid 1800 --expect true
	
    umount /data/mntlgs -l
}

function 1900() {
    rm -rf /data/lgs1900
    mkdir -p /data/lgs1900
    mkdir -p /data/mntlgs1900

    touch /data/lgs1900/test.txt

    mount -t sharefs /data/lgs1900 /data/mntlgs1900 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/"
	
	# Can be used kongge
	./dectool --cmd set --tokenid 1900 --path "/ aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc " --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/ " --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/ aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc " --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/ " --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/ aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc " --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/ " --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/ aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc " --expect true
	./dectool --cmd delete --tokenid 1900 --path "/ " --expect true
	
	# Can be used 1234567890
	./dectool --cmd set --tokenid 1900 --path "/1234567890aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb1234567890cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc1234567890" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/1234567890" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/1234567890aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb1234567890cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc1234567890" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/1234567890" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/1234567890aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb1234567890cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc1234567890" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/1234567890" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/1234567890aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb1234567890cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc1234567890" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/1234567890" --expect true
	
	# Can be used !
	./dectool --cmd set --tokenid 1900 --path "/!aabbcc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb!cc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc!" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/!" --mode 2 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/!aabbcc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb!cc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc!" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/!" --mode 2 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/!aabbcc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb!cc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc!" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/!" --mode 2 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/!aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb!cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc!" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/!" --expect true
	
	# Can be used @
	./dectool --cmd set --tokenid 1900 --path "/@aabbcc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb@cc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc@" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/@" --mode 2 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/@aabbcc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb@cc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc@" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/@" --mode 2 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/@aabbcc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb@cc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc@" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/@" --mode 2 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/@aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb@cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc@" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/@" --expect true
	
	# Can be used #
	./dectool --cmd set --tokenid 1900 --path "/#aabbcc" --mode 3 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb#cc" --mode 3 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc#" --mode 3 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/#" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/#aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb#cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc#" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/#" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/#aabbcc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb#cc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc#" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/#" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/#aabbcc" --mode 3 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb#cc" --mode 3 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc#" --mode 3 --expect true
	./dectool --cmd query --tokenid 1900 --path "/#" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/#aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb#cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc#" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/#" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/#aabbcc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb#cc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc#" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/#" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/#aabbcc" --mode 3 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb#cc" --mode 3 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc#" --mode 3 --expect true
	./dectool --cmd check --tokenid 1900 --path "/#" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/#aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb#cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc#" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/#" --expect true
	
	# Can be used $
	./dectool --cmd set --tokenid 1900 --path "/\$aabbcc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb$cc" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc$" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/$" --mode 2 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/\$aabbcc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb$cc" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc$" --mode 2 --expect true
	./dectool --cmd query --tokenid 1900 --path "/$" --mode 2 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/\$aabbcc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb$cc" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc$" --mode 2 --expect true
	./dectool --cmd check --tokenid 1900 --path "/\$" --mode 2 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/\$aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb$cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc\$" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/\$" --expect true
	
	# Can be used %
	./dectool --cmd set --tokenid 1900 --path "/%aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb%cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc%" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/%" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/%aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb%cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc%" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/%" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/%aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb%cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc%" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/%" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/%aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb%cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc%" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/%" --expect true
	
	# Can be used ^
	./dectool --cmd set --tokenid 1900 --path "/^aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb^cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc^" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/^" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/^aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb^cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc^" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/^" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/^aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb^cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc^" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/^" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/^aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb^cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc^" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/^" --expect true
	
	# Can be used &
	./dectool --cmd set --tokenid 1900 --path "/&aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb&cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc&" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/&" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/&aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb&cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc&" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/&" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/&aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb&cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc&" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/&" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/&aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb&cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc&" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/&" --expect true
	
	# Can be used ()
	./dectool --cmd set --tokenid 1900 --path "/()aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/(aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/)aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb()cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb(cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb)cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc()" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc)" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc(" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb(ddee)cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/()" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/(" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/)" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/()aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/(aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/)aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb()cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb(cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb)cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc()" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc)" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc(" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb(ddee)cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/()" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/(" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/)" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/()aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/(aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/)aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb()cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb(cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb)cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc()" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc)" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc(" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb(ddee)cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/()" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/(" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/)" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/()aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/(aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/)aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb()cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb(cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb)cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc()" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc)" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc(" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb(ddee)cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/()" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/(" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/)" --expect true
	
	# Can be used -
	./dectool --cmd set --tokenid 1900 --path "/-aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb-cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc-" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/-" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/-aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb-cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc-" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/-" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/-aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb-cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc-" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/-" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/-aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb-cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc-" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/-" --expect true
	
	# Can be used _
	./dectool --cmd set --tokenid 1900 --path "/_aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb_cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc_" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/_" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/_aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb_cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc_" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/_" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/_aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb_cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc_" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/_" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/_aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb_cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc_" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/_" --expect true
	
	# Can be used =
	./dectool --cmd set --tokenid 1900 --path "/=aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb=cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc=" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/=" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/=aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb=cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc=" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/=" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/=aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb=cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc=" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/=" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/=aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb=cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc=" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/=" --expect true
	
	# Can be used +
	./dectool --cmd set --tokenid 1900 --path "/+aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb+cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc+" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/+" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/+aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb+cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc+" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/+" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/+aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb+cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc+" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/+" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/+aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb+cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc+" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/+" --expect true
	
	# Can be used []
	./dectool --cmd set --tokenid 1900 --path "/[]aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/[aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/]aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb[]cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb[cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb]cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc[]" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc[" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc]" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb[ddee]cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/[]" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/[" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/]" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/[]aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/[aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/]aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb[]cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb[cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb]cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc[]" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc[" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc]" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb[ddee]cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/[]" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/[" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/]" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/[]aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/[aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/]aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb[]cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb[cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb]cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc[]" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc[" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc]" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb[ddee]cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/[]" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/[" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/]" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/[]aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/[aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/]aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb[]cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb[cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb]cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc[]" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc[" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc]" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb[ddee]cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/[]" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/[" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/]" --expect true
	
	# Can be used {}
	./dectool --cmd set --tokenid 1900 --path "/{}aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/{aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/}aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb{}cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb{cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb}cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc{}" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc{" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc}" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb{ddee}cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/{}" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/{" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/}" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/{}aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/{aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/}aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb{}cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb{cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb}cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc{}" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc{" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc}" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb{ddee}cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/{}" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/{" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/}" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/{}aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/{aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/}aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb{}cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb{cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb}cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc{}" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc{" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc}" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb{ddee}cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/{}" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/{" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/}" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/{}aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/{aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/}aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb{}cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb{cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb}cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc{}" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc{" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc}" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb{ddee}cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/{}" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/{" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/}" --expect true
	
	# Can be used ;
	./dectool --cmd set --tokenid 1900 --path "/;aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb;cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc;" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/;" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/;aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb;cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc;" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/;" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/;aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb;cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc;" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/;" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/;aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb;cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc;" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/;" --expect true
	
	# Can be used ''
	./dectool --cmd set --tokenid 1900 --path "/''aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb'cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc''" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/'aabbcc'" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/''" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/''aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb'cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc''" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/'aabbcc'" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/''" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/''aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb'cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc''" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/'aabbcc'" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/''" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/''aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb'cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc''" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/''" --expect true
	
	# Can be used ,
	./dectool --cmd set --tokenid 1900 --path "/,aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb,cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc," --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/," --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/,aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb,cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc," --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/," --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/,aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb,cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc," --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/," --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/,aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb,cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc," --expect true
	./dectool --cmd delete --tokenid 1900 --path "/," --expect true
	
	# Can be used .
	./dectool --cmd set --tokenid 1900 --path "/.aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb.cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc." --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/." --mode 1 --persist true --expect false
	
	./dectool --cmd query --tokenid 1900 --path "/.aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb.cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc." --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/." --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1900 --path "/.aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb.cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc." --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/." --mode 1 --expect false
	
	./dectool --cmd delete --tokenid 1900 --path "/.aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb.cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc." --expect true
	./dectool --cmd delete --tokenid 1900 --path "/." --expect false
	
	# Can be used `
	./dectool --cmd set --tokenid 1900 --path "/``aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb``cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc``" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/``" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/``aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb``cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc``" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/``" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/``aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb``cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc``" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/``" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1900 --path "/``aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/``" --expect true

	# Can be used ~
	./dectool --cmd set --tokenid 1900 --path "/~aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabb~cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/aabbcc~" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1900 --path "/~" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/~aabbcc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabb~cc" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/aabbcc~" --mode 1 --expect true
	./dectool --cmd query --tokenid 1900 --path "/~" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1900 --path "/~aabbcc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabb~cc" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/aabbcc~" --mode 1 --expect true
	./dectool --cmd check --tokenid 1900 --path "/~" --mode 1 --expect true
	
	./dectool --cmd query --tokenid 1900 --path "/~" --mode 2 --expect false
	./dectool --cmd query --tokenid 1900 --path "/~" --mode 3 --expect false
	./dectool --cmd check --tokenid 1900 --path "/~" --mode 2 --expect false
	./dectool --cmd check --tokenid 1900 --path "/~" --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 1900 --path "/~aabbcc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabb~cc" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/aabbcc~" --expect true
	./dectool --cmd delete --tokenid 1900 --path "/~" --expect true

	./dectool --cmd destroy --tokenid 1900 --expect true
	
    umount /data/mntlgs1900 -l
}

function 1910() {
    rm -rf /data/lgs1910
    mkdir -p /data/lgs1910
    mkdir -p /data/mntlgs1910

    touch /data/lgs1910/test.txt 

    mount -t sharefs /data/lgs1910 /data/mntlgs1910 -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/"

    #Cannot be used  
	./dectool --cmd set --tokenid 1910 --path "y" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "//" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "///" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "////" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path ".." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "..." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/.." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/..." --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/...." --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/......" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "./" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "../" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path ".../" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "..../" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/./" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/../" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1910 --path "/.../" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/....../" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/......b/" --mode 1 --persist true --expect true
	
	
	./dectool --cmd query --tokenid 1910 --path "y" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "//" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "///" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "////" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "." --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path ".." --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "..." --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/." --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/.." --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/..." --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/...." --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/......" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "./" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "../" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path ".../" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/./" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/../" --mode 1 --expect false
	./dectool --cmd query --tokenid 1910 --path "/.../" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/....../" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/......b/" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1910 --path "y" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "//" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "///" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "////" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "." --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path ".." --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "..." --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/." --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/.." --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/..." --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/...." --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/......" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "./" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "../" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path ".../" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/./" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/../" --mode 1 --expect false
	./dectool --cmd check --tokenid 1910 --path "/.../" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/....../" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/......b/" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1910 --path "y" --expect false
	./dectool --cmd delete --tokenid 1910 --path "//" --expect false
	./dectool --cmd delete --tokenid 1910 --path "///" --expect false
	./dectool --cmd delete --tokenid 1910 --path "////" --expect false
	./dectool --cmd delete --tokenid 1910 --path "." --expect false
	./dectool --cmd delete --tokenid 1910 --path ".." --expect false
	./dectool --cmd delete --tokenid 1910 --path "..." --expect false
	./dectool --cmd delete --tokenid 1910 --path "/." --expect false
	./dectool --cmd delete --tokenid 1910 --path "/.." --expect false
	./dectool --cmd delete --tokenid 1910 --path "/..." --expect true
	./dectool --cmd delete --tokenid 1910 --path "/...." --expect true
	./dectool --cmd delete --tokenid 1910 --path "/......" --expect true
	./dectool --cmd delete --tokenid 1910 --path "./" --expect false
	./dectool --cmd delete --tokenid 1910 --path "../" --expect false
	./dectool --cmd delete --tokenid 1910 --path ".../" --expect false
	./dectool --cmd delete --tokenid 1910 --path "/./" --expect false
	./dectool --cmd delete --tokenid 1910 --path "/../" --expect false
	#./dectool --cmd delete --tokenid 1910 --path "/.../"  --expect true
	#./dectool --cmd delete --tokenid 1910 --path "/....../"  --expect true
	./dectool --cmd delete --tokenid 1910 --path "/......b/"  --expect true
	
	#Cannot be used  \ 
	./dectool --cmd set --tokenid 1910 --path "/\\aabb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aa\\bb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb\\" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/\\" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1910 --path "/\aabb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aa\bb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aabb\\" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/\\" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1910 --path "/\aabb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aa\bb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aabb\\" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/\\" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1910 --path "/\aabb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aa\bb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aabb\\" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/\\" --expect true
	
	#Cannot be used  |
	./dectool --cmd set --tokenid 1910 --path "/|aabb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aa|bb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb|" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/|" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1910 --path "/|aabb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aa|bb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aabb|" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/|" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1910 --path "/|aabb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aa|bb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aabb|" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/|" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1910 --path "/|aabb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aa|bb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aabb|" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/|" --expect true
	
	#Cannot be used  :
	./dectool --cmd set --tokenid 1910 --path "/:aabb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aa:bb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb:" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/:" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/://" --mode 1 --persist true --expect false
	
	./dectool --cmd query --tokenid 1910 --path "/:aabb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aa:bb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aabb:" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/:" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/://" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 1910 --path "/:aabb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aa:bb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aabb:" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/:" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/://" --mode 1 --expect false
	
	./dectool --cmd delete --tokenid 1910 --path "/:aabb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aa:bb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aabb:" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/:" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/://" --expect false
	
	#Cannot be used  <>
	./dectool --cmd set --tokenid 1910 --path "/<>aabb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aa<>bb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb<>" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/a<ab>b" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/<>" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1910 --path "/<>aabb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aa<>bb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aabb<>" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/a<ab>b" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/<>" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1910 --path "/<>aabb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aa<>bb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aabb<>" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/a<ab>b" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/<>" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1910 --path "/<>aabb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aa<>bb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aabb<>" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/a<ab>b" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/<>" --expect true
	
	#Cannot be used  ?
	./dectool --cmd set --tokenid 1910 --path "/?aabb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aa?bb" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb?" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/?" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1910 --path "/?aabb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aa?bb" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/aabb?" --mode 1 --expect true
	./dectool --cmd query --tokenid 1910 --path "/?" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1910 --path "/?aabb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aa?bb" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/aabb?" --mode 1 --expect true
	./dectool --cmd check --tokenid 1910 --path "/?" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1910 --path "/?aabb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aa?bb" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/aabb?" --expect true
	./dectool --cmd delete --tokenid 1910 --path "/?" --expect true
	
	# Can be used *
	./dectool --cmd set --tokenid 1910 --path "/*aabbcc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabb*cc" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/aabbcc*/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*/*/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*/*/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/data/*/A" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/**/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1910 --path "/*test*tset/" --mode 1 --persist true --expect true

    ./dectool --cmd delete --tokenid 1910 --path "/*aabbcc" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/aabb*cc" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/aabbcc*" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/*/" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/*/*/" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/*/*/*" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/**/" --expect true
    ./dectool --cmd delete --tokenid 1910 --path "/*test*tset/" --expect true

	./dectool --cmd destroy --tokenid 1910 --expect true
	
    umount /data/mntlgs1910 -l
}

function 1920() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/tmp
    
    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/tmp -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/tmp"
	
	# Can be used /data/tmp/test/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/test/" --expect true
	
	# Can be used /data/tmp/test
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/test" --expect true
	
	# Can be used /data/tmp/test/*
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/*" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/test/*" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/*" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/*" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/test/*" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/*" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/*" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/test/*" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/test/*" --expect true
	
	# Can be used /data/tmp/*/tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/tmp" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/tmp" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/tmp" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/tmp" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/tmp" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/tmp" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/tmp" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/tmp" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/tmp" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/tmp" --expect true
	
	# Can be used /data/tmp/./tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/./tmp" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/./tmp" --mode 2 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/./tmp" --mode 3 --persist true --expect false
	
	/data/dectool --cmd query --tokenid 1920 --path "/data/tmp/./tmp" --mode 1 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/./tmp" --mode 2 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/./tmp" --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/./tmp" --mode 1 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/./tmp" --mode 2 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/./tmp" --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/./tmp" --expect false
	
	# Can be used /data/tmp/../tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/../tmp" --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/../tmp" --mode 2 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/../tmp" --mode 3 --persist true --expect false
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/../tmp" --mode 1 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/../tmp" --mode 2 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/../tmp" --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/../tmp" --mode 1 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/../tmp" --mode 2 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/../tmp" --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/../tmp" --expect false
	
	# Can be used /data/tmp/back./tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./tmp" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./tmp" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./tmp" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./tmp" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./tmp" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./tmp" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./tmp" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./tmp" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./tmp" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/back./tmp" --expect true
	
	# Can be used /data/tmp/back../tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back../tmp" --mode 1 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/back../tmp" --expect true
	
	# Can be used /data/tmp/back./.
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./." --mode 2 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./." --mode 3 --persist true --expect false
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./." --mode 1 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./." --mode 2 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./." --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./." --mode 1 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./." --mode 2 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./." --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/back./." --expect false
	
	# Can be used /data/tmp/back./..
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./.." --mode 1 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./.." --mode 2 --persist true --expect false
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/back./.." --mode 3 --persist true --expect false
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./.." --mode 1 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./.." --mode 2 --expect false
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/back./.." --mode 3 --expect false
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./.." --mode 1 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./.." --mode 2 --expect false
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/back./.." --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/back./.." --expect false
	
	# Can be used /data/tmp/*/back../tmp
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/back../tmp" --expect true
	
	# Can be used /data/tmp/*/back../tmp*/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/back../tmp*/" --expect true
	
	# Can be used /data/tmp/*/A/*
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/A/*" --expect true
	
	# Can be used /data/tmp/*/A/*/*
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/*" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/A/*/*" --expect true
	
	
	# Can be used /data/tmp/*/A/*/B
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/*/A/*/B" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/*/A/*/B" --expect true
	
	# Can be used /data/tmp/@&/A/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&/A/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&/A/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&/A/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&/A/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&/A/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&/A/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&/A/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&/A/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&/A/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/@&/A/" --expect true
	
	# Can be used /data/tmp/@&</A/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&</A/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&</A/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&</A/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&</A/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&</A/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&</A/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&</A/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&</A/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&</A/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/@&</A/" --expect true
	
	# Can be used /data/tmp/@&?/A/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&?/A/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/@&?/A/" --expect true
	
	# Can be used /data/tmp/@&\/A/
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 3 --persist true --expect true
	
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 1 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 2 --expect true
	./dectool --cmd query --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 3 --expect true
	
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 1 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 2 --expect true
	./dectool --cmd check --tokenid 1920 --path "/data/tmp/@&\/A/" --mode 3 --expect true
	
	./dectool --cmd delete --tokenid 1920 --path "/data/tmp/@&\/A/" --expect true
	
	umount /data/tmp -l
}

function 2000() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/"

    ./dectool --cmd set --tokenid 2000 --path " / " --mode 1 --persist true --expect false
	./dectool --cmd check --tokenid 2000 --path "/" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 2000 --expect true
	
    umount /data/mntlgs -l
}

function 2100() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/"

    ./dectool --cmd set --tokenid 2100 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklm" --mode 1 --persist true --expect false
	
	./dectool --cmd check --tokenid 2100 --path "/" --mode 3 --expect false
	
	./dectool --cmd check --tokenid 2100 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklm" --mode 1 --expect false
	
	./dectool --cmd query --tokenid 2100 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklm" --mode 1 --expect false
	
	./dectool --cmd check --tokenid 2100 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklm" --mode 2 --expect false
	
	./dectool --cmd query --tokenid 2100 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklm" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 2100 --expect true
	
    umount /data/mntlgs -l
}

function 2200() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/"

    ./dectool --cmd set --tokenid 2200 --path "/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwweeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrrrrrrrrrrrrrrrrrrrrrrrqqqqqqjuquuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpppppppppppppppppppppppppppaabbccddeeffggkklmm" --mode 1 --persist true --expect false

	./dectool --cmd destroy --tokenid 2200 --expect true
	
    umount /data/mntlgs -l
}

function 2300 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 2300 --path "/data/mntlgs" --mode 1 --persist true --expect true

    ./dectool --cmd read --tokenid 2300 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd write --tokenid 2300 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd rename --tokenid 2300 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd remove --tokenid 2300 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd check --tokenid 2300 --path "/data/mntlgs/test.txt" --mode 1 --expect true
    ./dectool --cmd check --tokenid 2300 --path "/data/mntlgs/test.txt" --mode 3 --expect false

	./dectool --cmd destroy --tokenid 2300 --expect true

    umount /data/mntlgs -l
}

function 2400 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 2400 --path "/data/mntlgs" --mode 1 --persist true --expect true

    ./dectool --cmd read --tokenid 2400 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd write --tokenid 2400 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd rename --tokenid 2400 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd remove --tokenid 2400 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd check --tokenid 2400 --path "/data/mntlgs/test.txt" --mode 1 --expect true
    ./dectool --cmd check --tokenid 2400 --path "/data/mntlgs/test.txt" --mode 3 --expect false

	./dectool --cmd destroy --tokenid 2400 --expect true

    umount /data/mntlgs -l
}


function 2500 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 2500 --path "/data/mntlgs" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 2500 --path "/data/mntlgs/test.txt" --mode 2 --expect true
	
	./dectool --cmd check --tokenid 2500 --path "/data/mntlgs/test.txt" --mode 3 --expect false
	
	./dectool --cmd read --tokenid 2500 --path "/data/mntlgs/test.txt" --expect false

    ./dectool --cmd write --tokenid 2500 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd rename --tokenid 2500 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd remove --tokenid 2500 --path "/data/mntlgs/test1.txt" --expect true
	
	./dectool --cmd destroy --tokenid 2500 --expect true

    umount /data/mntlgs -l
}

function 2600 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 2600 --path "/data/mntlgs" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 2600 --path "/data/mntlgs/test.txt" --mode 3 --expect true
	
	./dectool --cmd read --tokenid 2600 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd write --tokenid 2600 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd remove --tokenid 2600 --path "/data/mntlgs/test1.txt" --expect true
	
	./dectool --cmd delete --tokenid 2600 --path "/data/mntlgs" --expect true
	
	./dectool --cmd read --tokenid 2600 --path "/data/mntlgs/test.txt" --expect false
    ./dectool --cmd write --tokenid 2600 --path "/data/mntlgs/test.txt" --expect false
    ./dectool --cmd rename --tokenid 2600 --path "/data/mntlgs/test.txt" --expect false
    ./dectool --cmd remove --tokenid 2600 --path "/data/mntlgs/test1.txt" --expect false
	
	./dectool --cmd set --tokenid 2600 --path "/data/mntlgs" --mode 2 --persist true --expect true
	./dectool --cmd check --tokenid 2600 --path "/data/mntlgs/test.txt" --mode 2 --expect true
	
	./dectool --cmd destroy --tokenid 2600 --expect true
    umount /data/mntlgs -l
    
}

function 2700 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"
	
	./dectool --cmd set --tokenid 2700 --path "/data/mntlgs" --mode 1 --persist true --expect true
	
    ./dectool --cmd read --tokenid 2700 --path "/data/mntlgs/test.txt" --expect true
	./dectool --cmd check --tokenid 2700 --path "/data/mntlgs/test.txt" --mode 1 --expect true
	./dectool --cmd check --tokenid 2700 --path "/data/mntlgs/test.txt" --mode 2 --expect false
    ./dectool --cmd write --tokenid 2700 --path "/data/mntlgs/test.txt" --expect false
    ./dectool --cmd rename --tokenid 2700 --path "/data/mntlgs/test.txt" --expect false
    ./dectool --cmd remove --tokenid 2700 --path "/data/mntlgs/test1.txt" --expect false
	
    ./dectool --cmd set --tokenid 2700 --path "/data/mntlgs" --mode 2 --persist true --expect true

	./dectool --cmd read --tokenid 2700 --path "/data/mntlgs/test.txt" --expect true
    ./dectool --cmd write --tokenid 2700 --path "/data/mntlgs/test.txt" --expect true
	./dectool --cmd check --tokenid 2700 --path "/data/mntlgs/test.txt" --mode 3 --expect true
    ./dectool --cmd rename --tokenid 2700 --path "/data/mntlgs/test.txt" --expect true
    ./dectool --cmd remove --tokenid 2700 --path "/data/mntlgs/test1.txt" --expect true
	./dectool --cmd check --tokenid 2700 --path "/data/mntlgs/test1.txt" --mode 3 --expect true
	
	./dectool --cmd destroy --tokenid 2700 --expect true
	
    umount /data/mntlgs -l
}

function 2800 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /storage/Users  

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /storage/Users -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/storage/Users"
	
	./dectool --cmd set --tokenid 2800 --path "/storage/Users" --mode 1 --persist true --expect true
	./dectool --cmd check --tokenid 2800 --path "/storage/Users" --mode 1 --expect true
	./dectool --cmd check --tokenid 2800 --path "/storage/Users" --mode 3 --expect false
	
    ./dectool --cmd read --tokenid 2800 --path "/storage/Users/test.txt" --expect true
    ./dectool --cmd write --tokenid 2800 --path "/storage/Users/test.txt" --expect false
	
	./dectool --cmd destroy --tokenid 2800 --expect true
	
    umount /storage/Users -l
}

function 2900 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /storage/Share

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /storage/Share -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/storage/Share"
	
	./dectool --cmd set --tokenid 2900 --path "/storage/Share" --mode 2 --persist true --expect true
	
    ./dectool --cmd read --tokenid 2900 --path "/storage/Share/test.txt" --expect false
    ./dectool --cmd write --tokenid 2900 --path "/storage/Share/test.txt" --expect true
	
	./dectool --cmd check --tokenid 2900 --path "/storage/Share" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 2900 --expect true
	
    umount /storage/Share -l
}

function 3000 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /storage/External

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /storage/External -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/storage/External"
	
	./dectool --cmd set --tokenid 3000 --path "/storage/External" --mode 3 --persist true --expect true
	
    ./dectool --cmd read --tokenid 3000 --path "/storage/External/test.txt" --expect true
    ./dectool --cmd write --tokenid 3000 --path "/storage/External/test.txt" --expect true
	
	./dectool --cmd check --tokenid 3000 --path "/storage/External" --mode 3 --expect true
	
	./dectool --cmd rename --tokenid 3000 --path "/storage/External/test.txt" --expect true
    ./dectool --cmd remove --tokenid 3000 --path "/storage/External/test1.txt" --expect true
	
	./dectool --cmd destroy --tokenid 3000 --expect true
	
    umount /storage/External -l
}

function 3100 {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /storage/hmdfs

    touch /data/lgs/test.txt
	touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /storage/hmdfs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/storage/hmdfs"
	
	./dectool --cmd set --tokenid 3100 --path "/storage/hmdfs" --mode 1 --persist true --expect true
	
    ./dectool --cmd read --tokenid 3100 --path "/storage/hmdfs/test.txt" --expect true
    ./dectool --cmd write --tokenid 3100 --path "/storage/hmdfs/test.txt" --expect false
	
	./dectool --cmd check --tokenid 3100 --path "/storage/hmdfs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 3100 --expect true
	
    umount /storage/hmdfs -l
}

function 3300() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 3300 --path "" --mode 3 --persist true --expect false
	
	./dectool --cmd check --tokenid 3300 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 3300 --expect true
	
    umount /data/mntlgs -l
}

function 3400() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    /data/dectool --cmd set --tokenid 3400 --path "/data/mntlgs" --mode 1000000 --persist true --expect true
	
	./dectool --cmd check --tokenid 3400 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 3400 --expect true
	
    umount /data/mntlgs -l
}

function 3500() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data
	./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 3500  --mode 2 --persist true --expect false
	
	./dectool --cmd check --tokenid 3500 --path "/data/mntlgs" --mode 3 --expect false
	
	./dectool --cmd destroy --tokenid 3500 --expect true
	
    umount /data/mntlgs -l
}

function 3600() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
	mkdir -p /data/mntlgs/mn

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs/mn -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 3600 --path "/data/mntlgs" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 3600 --path "/data/mntlgs" --mode 3 --expect true

    ./dectool --cmd check --tokenid 3600 --path "/data/mntlgs/mn" --mode 3 --expect true
	
	./dectool --cmd read --tokenid 3600 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd write --tokenid 3600 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd rename --tokenid 3600 --path "/data/mntlgs/mn/test.txt" --expect true
	
	./dectool --cmd destroy --tokenid 3600 --expect true

    umount /data/mntlgs/mn -l
}

function 3700() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
	mkdir -p /data/mntlgs/mn

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs/mn -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 3700 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 3700 --path "/data/mntlgs/mn" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 3700 --path "/data/mntlgs" --mode 1 --expect true

    ./dectool --cmd check --tokenid 3700 --path "/data/mntlgs/mn" --mode 1 --expect true
	./dectool --cmd check --tokenid 3700 --path "/data/mntlgs/mn" --mode 2 --expect false
	./dectool --cmd check --tokenid 3700 --path "/data/mntlgs/mn" --mode 3 --expect false
	
	./dectool --cmd read --tokenid 3700 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd write --tokenid 3700 --path "/data/mntlgs/mn/test.txt" --expect false

    ./dectool --cmd remove --tokenid 3700 --path "/data/mntlgs/mn/test.txt" --expect false
	
	./dectool --cmd destroy --tokenid 3700 --expect true

    umount /data/mntlgs/mn -l
}

function 3800() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
	mkdir -p /data/mntlgs/mn
	
    touch /data/lgs/test.txt
    touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs/mn -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"
	

    ./dectool --cmd set --tokenid 3800 --path "/data/mntlgs" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 3800 --path "/data/mntlgs/mn" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 3800 --path "/data/mntlgs" --mode 2 --expect true

    ./dectool --cmd check --tokenid 3800 --path "/data/mntlgs/mn" --mode 2 --expect true
	./dectool --cmd check --tokenid 3800 --path "/data/mntlgs/mn" --mode 3 --expect false
	
	./dectool --cmd read --tokenid 3800 --path "/data/mntlgs/mn/test.txt" --expect false

    ./dectool --cmd write --tokenid 3800 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd rename --tokenid 3800 --path "/data/mntlgs/mn/test.txt" --expect true
	
	./dectool --cmd remove --tokenid 3800 --path "/data/mntlgs/mn/test1.txt" --expect true
	
	./dectool --cmd destroy --tokenid 3800 --expect true

    umount /data/mntlgs/mn -l
}

function 3900() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
	mkdir -p /data/mntlgs/mn
	
    touch /data/lgs/test.txt
    touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs/mn -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"
	
    ./dectool --cmd set --tokenid 3900 --path "/data/mntlgs" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 3900 --path "/data/mntlgs/mn" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 3900 --path "/data/mntlgs" --mode 1 --expect true

	./dectool --cmd delete --tokenid 3900 --path "/data/mntlgs" --expect true
	
	./dectool --cmd check --tokenid 3900 --path "/data/mntlgs" --mode 1 --expect false

	./dectool --cmd check --tokenid 3900 --path "/data/mntlgs/mn" --mode 3 --expect true
	
	./dectool --cmd read --tokenid 3900 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd write --tokenid 3900 --path "/data/mntlgs/mn/test.txt" --expect true

    ./dectool --cmd rename --tokenid 3900 --path "/data/mntlgs/mn/test.txt" --expect true
	
	./dectool --cmd remove --tokenid 3900 --path "/data/mntlgs/mn/test1.txt" --expect true
	
	./dectool --cmd destroy --tokenid 3900 --expect true

    umount /data/mntlgs/mn -l
}

function 4000() {
    rm -rf /data/lgs4000
    mkdir -p /data/lgs4000
    mkdir -p /data/mntlgs4000
	
    touch /data/lgs4000/test4000.txt

    mount -t sharefs /data/lgs4000 /data/mntlgs4000 -o override_support_delete -o user_id=100

    cd /data

	./dectool --cmd read --tokenid 4000 --path "/data/mntlgs4000/test4000.txt" --expect true

    ./dectool --cmd write --tokenid 4000 --path "/data/mntlgs4000/test4000.txt" --expect true
	
	/data/dectool --cmd check --tokenid 4000 --path "/data/mntlgs4000/test4000.txt" --mode 3 --expect true
	
	./dectool --cmd destroy --tokenid 4000 --expect true

    umount /data/mntlgs4000 -l
}

function 4100() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4100 --path "/data/mntlgs" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 4100 --path "/data/mntlgs/test.txt" --mode 3 --expect false

    ./dectool --cmd write --tokenid 4100 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd destroy --tokenid 4100 --expect true
	
    umount /data/mntlgs -l
}

function 4200() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4200 --path "/data/mntlgs" --mode 2 --persist true --expect true
	
	./dectool --cmd check --tokenid 4200 --path "/data/mntlgs/test.txt" --mode 3 --expect false

    ./dectool --cmd write --tokenid 4200 --path "/data/mntlgs/test.txt" --expect true

	./dectool --cmd destroy --tokenid 4200 --expect true

    umount /data/mntlgs -l
}

function 4300() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4300 --path "/data/mntlgs" --mode 2 --persist true --expect true
	
	./dectool --cmd check --tokenid 4300 --path "/data/mntlgs" --mode 3 --expect false

    ./dectool --cmd read --tokenid 4300 --path "/data/mntlgs/test.txt" --expect true

	./dectool --cmd destroy --tokenid 4300 --expect true
	
    umount /data/mntlgs -l
}

function 4400() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4400 --path "/data/mntlgs" --mode 1 --persist true --expect true
	
	./dectool --cmd check --tokenid 4400 --path "/data/mntlgs" --mode 3 --expect false

    ./dectool --cmd write --tokenid 4400 --path "/data/mntlgs/test.txt" --expect true
	
	./dectool --cmd destroy --tokenid 4400 --expect true

    umount /data/mntlgs -l
}

function 4500() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4500 --path "/data/mntlgs" --mode 2 --persist true --expect true
	
	./dectool --cmd check --tokenid 4500 --path "/data/mntlgs" --mode 3 --expect false

    ./dectool --cmd read --tokenid 4500 --path "/data/mntlgs/test.txt" --expect true
	
	./dectool --cmd destroy --tokenid 4500 --expect true

    umount /data/mntlgs -l
}

function 4600() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 4600 --path "/data/mntlgs" --mode 2 --persist true --expect true

    ./dectool --cmd write --tokenid 4600 --path "/data/mntlgs/test.txt" --expect true
	
	./dectool --cmd check --tokenid 4600 --path "/data/mntlgs/test.txt" --mode 3 --expect false

	./dectool --cmd destroy --tokenid 4600 --expect true

    umount /data/mntlgs -l
}

function 4900() {
    rm -rf /data/lgs
    mkdir -p /data/lgs/dir1
    mkdir -p /data/mntlgs4900
    touch /data/lgs/dir1/dir1test.txt
    touch /data/lgs/dir1/dir1test2.txt
    touch /data/lgs/test.txt
    touch /data/lgs/test2.txt

    cd /data

    mount -t sharefs /data/lgs /data/mntlgs4900 -o override_support_delete -o user_id=100

    /data/dectool --cmd constraint --path "/data/mntlgs4900"

    ./dectool --cmd set --tokenid 4900 --path "/data/mntlgs4900/test.txt" --mode 3 --persist true --expect true

    ./dectool --cmd set --tokenid 4900 --path "/data/mntlgs4900/test2.txt" --mode 1 --persist true --expect true

    ./dectool --cmd set --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test.txt" --mode 3 --persist true --expect true

    ./dectool --cmd set --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test2.txt" --mode 1 --persist true --expect true

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/test.txt" --mode 3  --expect true

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/test2.txt" --mode 1 --expect true

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/test2.txt" --mode 3 --expect false

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test.txt" --mode 3 --expect true

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test2.txt" --mode 1 --expect true

    ./dectool --cmd check --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test2.txt" --mode 3 --expect false

    ./dectool --cmd write --tokenid 4900 --path "/data/mntlgs4900/test.txt" --expect true

    ./dectool --cmd write --tokenid 4900 --path "/data/mntlgs4900/test2.txt" --expect false

    ./dectool --cmd write --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test.txt" --expect true

    ./dectool --cmd write --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test2.txt" --expect false

    ./dectool --cmd read --tokenid 4900 --path "/data/mntlgs4900/test.txt" --expect true

    ./dectool --cmd read --tokenid 4900 --path "/data/mntlgs4900/test2.txt" --expect true

    ./dectool --cmd read --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test.txt" --expect true

    ./dectool --cmd read --tokenid 4900 --path "/data/mntlgs4900/dir1/dir1test2.txt" --expect true

    ./dectool --cmd destroy --tokenid 4900 --expect true

    umount /data/mntlgs4900 -l
}

function 5400() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs

    touch /data/lgs/test.txt

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd read --tokenid 5400 --path "/data/mntlgs" --expect false

    ./dectool --cmd write --tokenid 5400 --path "/data/mntlgs/test.txt" --expect false

	./dectool --cmd set --tokenid 5400 --path "/data/mntlgs" --mode 2 --persist true --expect true
	
	./dectool --cmd check --tokenid 5400 --path "/data/mntlgs/test.txt" --mode 3 --expect false
	./dectool --cmd check --tokenid 5400 --path "/data/mntlgs/test.txt" --mode 2 --expect true
	
	./dectool --cmd destroy --tokenid 5400 --expect true

    umount /data/mntlgs -l
}

function 5500() {
    rm -rf /data/lgs
    mkdir -p /data/lgs
    mkdir -p /data/mntlgs
	mkdir -p /data/mntlgs/mn
	mkdir -p /data/mntlgs/mn/bb
	mkdir -p /data/mntlgs/mn/bb/aa

    touch /data/lgs/test.txt
    touch /data/lgs/test1.txt

    mount -t sharefs /data/lgs /data/mntlgs/mn/bb/aa -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 5500 --path "/data/mntlgs" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 5500 --path "/data/mntlgs" --mode 2 --expect true

    ./dectool --cmd check --tokenid 5500 --path "/data/mntlgs/mn/bb/aa" --mode 1 --expect false
	./dectool --cmd check --tokenid 5500 --path "/data/mntlgs/mn/bb/aa" --mode 2 --expect true
	./dectool --cmd check --tokenid 5500 --path "/data/mntlgs/mn/bb/aa" --mode 3 --expect false
	
	./dectool --cmd read --tokenid 5500 --path "/data/mntlgs/mn/bb/aa/test.txt" --expect false

    ./dectool --cmd write --tokenid 5500 --path "/data/mntlgs/mn/bb/aa/test.txt" --expect true
	
	./dectool --cmd rename --tokenid 5500 --path "/data/mntlgs/mn/bb/aa/test.txt" --expect true

    ./dectool --cmd remove --tokenid 5500 --path "/data/mntlgs/mn/bb/aa/test1.txt" --expect true
	
	./dectool --cmd destroy --tokenid 5500 --expect true

    umount /data/mntlgs/mn/bb/aa -l
}

function 5600() {
    rm -rf /data/lgs5600
    mkdir -p /data/lgs5600
    mkdir -p /data/mntlgs5600
	mkdir -p /data/mntlgs5600/mnm
	
    touch /data/lgs5600/test.txt

    mount -t sharefs /data/lgs5600 /data/mntlgs5600/mnm -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs5600"
	
    ./dectool --cmd set --tokenid 5600 --path "/data/mntlgs5600" --mode 1 --persist true --expect true
	./dectool --cmd set --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600" --mode 1 --expect true

    ./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 1 --expect true
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 2 --expect false
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 5600 --path "/data/mntlgs5600" --expect true
	
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600" --mode 1 --expect false

    ./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 1 --expect false
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 2 --expect true
	
	./dectool --cmd read --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect false

    ./dectool --cmd write --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect true

    ./dectool --cmd rename --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect true
	
	./dectool --cmd delete --tokenid 5600 --path "/data/mntlgs5600/mnm" --expect true
	
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 1 --expect false

    ./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 1 --expect false
	./dectool --cmd check --tokenid 5600 --path "/data/mntlgs5600/mnm" --mode 2 --expect false
	
	./dectool --cmd read --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect false

    ./dectool --cmd write --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect false

    ./dectool --cmd rename --tokenid 5600 --path "/data/mntlgs5600/mnm/test.txt" --expect false
	
	./dectool --cmd destroy --tokenid 5600 --expect true

    umount /data/mntlgs5600/mnm -l
}

function 5700() {
    rm -rf /data/lgss5700
    mkdir -p /data/lgss5700
    mkdir -p /data/mntlgs5700
	mkdir -p /data/mntlgs5700/mnq
	
    touch /data/lgss5700/test3.txt
    touch /data/lgss5700/test4.txt

    mount -t sharefs /data/lgss5700 /data/mntlgs5700/mnq -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs5700/mnq"
	
    ./dectool --cmd set --tokenid 5700 --path "/data/mntlgs5700" --mode 2 --persist true --expect true
	./dectool --cmd set --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 1 --persist true --expect true

    ./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700" --mode 2 --expect true

    ./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 1 --expect false
	./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 2 --expect true
	./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 3 --expect false
	
	./dectool --cmd delete --tokenid 5700 --path "/data/mntlgs5700" --expect true

	./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700" --mode 2 --expect true

    ./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 2 --expect false
	./dectool --cmd check --tokenid 5700 --path "/data/mntlgs5700/mnq" --mode 1 --expect true
	
	./dectool --cmd read --tokenid 5700 --path "/data/mntlgs5700/mnq/test3.txt" --expect true

    ./dectool --cmd write --tokenid 5700 --path "/data/mntlgs5700/mnq/test3.txt" --expect false

    ./dectool --cmd rename --tokenid 5700 --path "/data/mntlgs5700/mnq/test3.txt" --expect false
	
	./dectool --cmd remove --tokenid 5700 --path "/data/mntlgs5700/mnq/test4.txt" --expect false
	
	./dectool --cmd destroy --tokenid 5700 --expect true

    umount /data/mntlgs5700/mnq -l
}

function 5800() {
    rm -rf /data/lgs5800
    mkdir -p /data/lgs5800/**/**1
    mkdir -p "/data/lgs5800/*/*1"
    mkdir -p /data/mntlgs5800
    touch /data/lgs5800/**/**1/**1test.txt
    touch /data/lgs5800/test.txt
    touch "/data/lgs5800/*/*1/*1test.txt"
    mount -t sharefs /data/lgs5800 /data/mntlgs5800 -o override_support_delete -o user_id=100
    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs5800"
    ./dectool --cmd set --tokenid 5800 --path "/data/mntlgs5800/*/" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800" --mode 3 --expect false

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800/*" --mode 3 --expect true

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800/*/*1" --mode 3 --expect true

    # create new file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/testnew.txt" --expect false

    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/*/testnew.txt" --expect true

    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/*/*1/testnew.txt" --expect true
	
	./dectool --cmd readdir --tokenid 5800 --path "/data/mntlgs5800/*" --expect true

    # write exist file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/**/**1/**1test.txt" --expect false

    # write exist file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect false

    ./dectool --cmd read --tokenid 5800 --path "/data/mntlgs5800/**/**1/**1test.txt" --expect false

    ./dectool --cmd read --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect false
    ./dectool --cmd readdir --tokenid 5800 --path "/data/mntlgs5800/*" --expect true

    ./dectool --cmd copy --tokenid 5800 --path "/data/mntlgs5800/test.txt" --dstpath "/data/mntlgs5800/**/**1/**1test.txt" --expect false
	
	./dectool --cmd copy --tokenid 5800 --path "/data/mntlgs5800/*/*1/testnew.txt" --dstpath "/data/lgs5800/*/*1/*1test.txt" --expect true

    ./dectool --cmd remove --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect false

    ./dectool --cmd rename --tokenid 5800 --path "/data/mntlgs5800/**/**1/**1test.txt" --expect false

    ./dectool --cmd mkdir --tokenid 5800 --path "/data/mntlgs5800/*" --expect true

    ./dectool --cmd mkdir --tokenid 5800 --path "/data/mntlgs5800/**/**2" --expect false

    ./dectool --cmd destroy --tokenid 5800 --expect true

    umount /data/mntlgs5800 -l
}




function 58000() {
    rm -rf /data/lgs5800
    mkdir -p /data/lgs5800/dir1/dir11
    mkdir -p /data/lgs5800/dir2/dir21
    mkdir -p /data/mntlgs5800
    touch /data/lgs5800/dir1/dir11/dir11test.txt
    touch /data/lgs5800/test.txt
    touch /data/lgs5800/dir2/dir21/dir21test.txt
    mount -t sharefs /data/lgs5800 /data/mntlgs5800 -o override_support_delete -o user_id=100
    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs5800"
    ./dectool --cmd set --tokenid 5800 --path "/data/mntlgs5800/*/" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800" --mode 3 --expect false

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800/dir2" --mode 3 --expect false

    ./dectool --cmd check --tokenid 5800 --path "/data/mntlgs5800/dir2/dir21" --mode 3 --expect true

    # create new file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/testnew.txt" --expect false

    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/dir2/testnew.txt" --expect true

    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/dir2/dir21/testnew.txt" --expect true

    # write exist file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/dir1/dir11/dir11test.txt" --expect true

    # write exist file
    ./dectool --cmd write --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect true

    ./dectool --cmd read --tokenid 5800 --path "/data/mntlgs5800/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd read --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect true

    ./dectool --cmd copy --tokenid 5800 --path "/data/mntlgs5800/test.txt" --dstpath "/data/mntlgs5800/dir1/dir11/dir11test.txt" --expect true
	
	./dectool --cmd copy --tokenid 5800 --path "/data/mntlgs5800/test.txt" --dstpath "/data/lgs5800/dir2/dir21/dir21test.txt" --expect true

    ./dectool --cmd remove --tokenid 5800 --path "/data/mntlgs5800/test.txt" --expect false

    ./dectool --cmd rename --tokenid 5800 --path "/data/mntlgs5800/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd mkdir --tokenid 5800 --path "/data/mntlgs5800/dir2" --expect true

    ./dectool --cmd mkdir --tokenid 5800 --path "/data/mntlgs5800/dir1/dir12" --expect true

    ./dectool --cmd destroy --tokenid 5800 --expect true

    umount /data/mntlgs5800 -l
}

function 5900() {
    rm -rf /data/lgs
    mkdir -p /data/lgs/test1/test11
    mkdir -p /data/lgs/test1/test21
    mkdir -p /data/mntlgssa
	
    touch /data/lgs/test1/test11/test11test.txt
    touch /data/lgs/test.txt
    touch /data/lgs/test1/test21/test21test.txt
	
    mount -t sharefs /data/lgs /data/mntlgssa -o override_support_delete -o user_id=100
    cd /data

    ./dectool --cmd constraint --path "/data/mntlgssa"
    ./dectool --cmd set --tokenid 5900 --path "/data/mntlgssa/test1/test11" --mode 2 --persist true --expect true
    ./dectool --cmd set --tokenid 5900 --path "/data/mntlgssa/test1/test21" --mode 1 --persist true --expect true

    ./dectool --cmd check --tokenid 5900 --path "/data/mntlgssa" --mode 3 --expect false

    ./dectool --cmd check --tokenid 5900 --path "/data/mntlgssa/test1/test11" --mode 2 --expect true

    ./dectool --cmd check --tokenid 5900 --path "/data/mntlgssa/test1/test21" --mode 1 --expect true

    # create new file
    ./dectool --cmd write --tokenid 5900 --path "/data/mntlgssa/test1/test11/testnew.txt" --expect true

    ./dectool --cmd write --tokenid 5900 --path "/data/mntlgssa/test1/test21/testnew.txt" --expect false

    # write exist file
    ./dectool --cmd write --tokenid 5900 --path "/data/mntlgssa/test1/test11/test11test.txt" --expect true

    # write exist file
    ./dectool --cmd read --tokenid 5900 --path "/data/mntlgssa/test1/test11/test11test.txt" --expect false
    ./dectool --cmd read --tokenid 5900 --path "/data/mntlgssa/test1/test21/test21test.txt" --expect true

    ./dectool --cmd copy --tokenid 5900 --path "/data/mntlgssa/test1/test21/test21test.txt" --dstpath "/data/mntlgssa/test1/test11/qqqtest.txt" --expect true

    ./dectool --cmd destroy --tokenid 5900 --expect true

    umount /data/mntlgssa -l
}

function 6000() {
    rm -rf /data/lgs
    mkdir -p /data/lgs/dir1/dir11
    mkdir -p /data/mntlgs
    touch /data/lgs/dir1/dir11/dir11test.txt
    touch /data/lgs/dir1/dir1test.txt
    touch /data/lgs/dir1/dir1test2.txt
    touch /data/lgs/test.txt

    cd /data

    mount -t sharefs /data/lgs /data/mntlgs -o override_support_delete -o user_id=100

    ./dectool --cmd constraint --path "/data/mntlgs"

    ./dectool --cmd set --tokenid 6000 --path "/data/mntlgs" --mode 3 --persist true --expect true

    ./dectool --cmd check --tokenid 6000 --path "/data/mntlgs" --mode 3 --expect true

    ./dectool --cmd query --tokenid 6000 --path "/data/mntlgs" --mode 3 --expect true

    ./dectool --cmd write --tokenid 6000 --path "/data/mntlgs/newtest.txt" --expect true

    ./dectool --cmd write --tokenid 6000 --path "/data/mntlgs/dir1/dir11/newtest.txt" --expect true

    ./dectool --cmd write --tokenid 6000 --path "/data/mntlgs/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd write --tokenid 6000 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd read --tokenid 6000 --path "/data/mntlgs/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd read --tokenid 6000 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd copy --tokenid 6000 --path "/data/mntlgs/test.txt" --dstpath "/data/mntlgs/dstTest1.txt" --expect true

    ./dectool --cmd copy --tokenid 6000 --path "/data/mntlgs/test.txt" --dstpath "/data/lgs/dstTest11.txt" --expect true

    ./dectool --cmd mkdir --tokenid 6000 --path "/data/mntlgs/dir2" --expect true

    ./dectool --cmd mkdir --tokenid 6000 --path "/data/mntlgs/dir1/dir12" --expect true

    ./dectool --cmd rename --tokenid 6000 --path "/data/lgs/test.txt" --expect true

    ./dectool --cmd rename --tokenid 6000 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd rename --tokenid 6000 --path "/data/mntlgs/dir1/dir1test.txt" --expect true

    ./dectool --cmd rename --tokenid 6000 --path "/data/mntlgs/dir1/dir1test2.txt" --expect true

    ./dectool --cmd rename --tokenid 6000 --path "/data/mntlgs/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd remove --tokenid 6000 --path "/data/mntlgs/test.txt" --expect true

    ./dectool --cmd remove --tokenid 6000 --path "/data/mntlgs/dir1/dir1test.txt" --expect true

    ./dectool --cmd remove --tokenid 6000 --path "/data/mntlgs/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd destroy --tokenid 6000 --expect true

    umount /data/mntlgs -l
}

function 5000() {
    rm -rf /data/lgs5000
    mkdir -p /data/lgs5000/dir1/dir11
    mkdir -p /data/mntlgs5000
    touch /data/lgs5000/dir1/dir11/test.txt
    touch /data/lgs5000/dir1/dir1test.txt
    touch /data/lgs5000/test.txt
    mount -t sharefs /data/lgs5000 /data/mntlgs5000 -o override_support_delete -o user_id=100
    cd /data

    ./dectool --cmd constraint --path "/data/mntlgs5000"

    ./dectool --cmd set --tokenid 5000 --path "/data/mntlgs5000" --mode 2 --persist true --expect true

    ./dectool --cmd check --tokenid 5000 --path "/data/mntlgs5000" --mode 2 --expect true

    ./dectool --cmd write --tokenid 5000 --path "/data/mntlgs5000/test.txt" --expect true

    ./dectool --cmd write --tokenid 5000 --path "/data/mntlgs5000/testA.txt" --expect true

    ./dectool --cmd write --tokenid 5000 --path "/data/mntlgs5000/dir1/dir11/newtest.txt" --expect true

    ./dectool --cmd write --tokenid 5000 --path "/data/mntlgs5000/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd read --tokenid 5000 --path "/data/mntlgs5000/dir1/dir11/dir11test.txt" --expect false

    ./dectool --cmd read --tokenid 5000 --path "/data/mntlgs5000/test.txt" --expect false

    ./dectool --cmd copy --tokenid 5000 --path "/data/mntlgs5000/test.txt" --dstpath "/data/mntlgs5000/dstTest1.txt" --expect false

    ./dectool --cmd copy --tokenid 5000 --path "/data/mntlgs5000/test.txt" --dstpath "/data/lgs5000/dstTest11.txt" --expect false

    ./dectool --cmd mkdir --tokenid 5000 --path "/data/mntlgs5000/dir2" --expect true

    ./dectool --cmd mkdir --tokenid 5000 --path "/data/mntlgs5000/dir1/dir12" --expect true

    ./dectool --cmd rename --tokenid 5000 --path "/data/mntlgs5000/test.txt" --expect true

    ./dectool --cmd rename --tokenid 5000 --path "/data/mntlgs5000/dir1/dir11/test.txt" --expect true

    ./dectool --cmd remove --tokenid 5000 --path "/data/mntlgs5000/test.txt" --expect true

    ./dectool --cmd remove --tokenid 5000 --path "/data/mntlgs5000/dir1/dir1test.txt" --expect true

    ./dectool --cmd remove --tokenid 5000 --path "/data/mntlgs5000/dir1/dir11/dir11test.txt" --expect true

    ./dectool --cmd destroy --tokenid 5000 --expect true

    umount /data/mntlgs5000 -l
}

#查看读写文件
function 6100(){
    rm -rf /data/a
    mkdir -p /data/a/currentUser6100/appdata
    mkdir -p /data/a/currentUser6100/Desktop
    touch /data/a/currentUser6100/appdata/test.mp4
    touch /data/a/currentUser6100/Desktop/test.mp4
    touch /data/a/currentUser6100/test.mp4
    mkdir -p /data/mnta

    mount -t sharefs /data/a /data/mnta -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mnta/"

    ./dectool --cmd forced_prefix --path "/data/mnta/currentUser6100/appdata"

    ./dectool --cmd set --tokenid 6100 --path "/data/mnta/currentUser6100" --mode 3 --expect true

    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 1  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 2  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 3  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 1  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 2  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 3  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 1  --expect false
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 2  --expect false
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 3  --expect false

	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/test.mp4" --mode 2 --expect true

	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/Desktop/test.mp4" --mode 2 --expect true

	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --expect false
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 0 --expect false
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/el2/test.mp4" --mode 2 --expect false

    ./dectool --cmd set --tokenid 6100 --path "/data/mnta/currentUser6100/appdata" --mode 3 --expect true

    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 3  --expect true
	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2 --expect true
	
	./dectool --cmd delete --tokenid 6100 --path "/data/mnta/currentUser6100/appdata" --expect true
	
	./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1  --expect false
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2  --expect false
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 3  --expect false
	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect false
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2 --expect false
	
	./dectool --cmd set --tokenid 6100 --path "/data/mnta/currentUser6100/appdata" --mode 1 --expect true
	./dectool --cmd set --tokenid 6100 --path "/data/mnta/currentUser6100/appdata" --mode 2 --expect true
	./dectool --cmd set --tokenid 6100 --path "/data/mnta/currentUser6100/appdata" --mode 3 --expect true

    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2  --expect true
    ./dectool --cmd check --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 3  --expect true
	./dectool --cmd read --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6100 --path "/data/mnta/currentUser6100/appdata/test.mp4" --mode 2 --expect true
	
    ./dectool  --cmd destroy --tokenid 6100 

    umount /data/mnta/ -l
}

#设置读权限，查看读写文件
function 6200(){
    rm -rf /data/b
    mkdir -p /data/b/currentUser6200/appdata
    mkdir -p /data/b/currentUser6200/Desktop
    touch /data/b/currentUser6200/appdata/test.mp4
    touch /data/b/currentUser6200/Desktop/test.mp4
    touch /data/b/currentUser6200/test.mp4
    mkdir -p /data/mntb

    mount -t sharefs /data/b /data/mntb -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntb/"

    ./dectool --cmd forced_prefix --path "/data/mntb/currentUser6200/appdata"

    ./dectool --cmd set --tokenid 6200 --path "/data/mntb/currentUser6200" --mode 1 --expect true

    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 1 --expect true
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 2 --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 3 --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 1 --expect true
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 2 --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 3 --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/el2/test.mp4" --mode 1  --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/el2/test.mp4" --mode 2  --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/el2/test.mp4" --mode 3  --expect false

	./dectool --cmd read --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --expect false
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/test.mp4" --mode 2 --expect false

	./dectool --cmd read --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --expect false
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/Desktop/test.mp4" --mode 2 --expect false

    ./dectool --cmd read --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --expect false
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 2 --expect false

    ./dectool --cmd set --tokenid 6200 --path "/data/mntb/currentUser6200/appdata" --mode 1 --expect true

    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 1  --expect true
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 2  --expect false
    ./dectool --cmd check --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 3  --expect false

    ./dectool --cmd read --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --expect false
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 1 --expect true
	./dectool --cmd access --tokenid 6200 --path "/data/mntb/currentUser6200/appdata/test.mp4" --mode 2 --expect false

    ./dectool  --cmd destroy --tokenid 6200 

    umount /data/mntb/ -l
}

#设置写权限，查看读写文件
function 6300(){
    rm -rf /data/c
    mkdir -p /data/c/currentUser6300/appdata
    mkdir -p /data/c/currentUser6300/Desktop
    touch /data/c/currentUser6300/appdata/test.mp4
    touch /data/c/currentUser6300/Desktop/test.mp4
    touch /data/c/currentUser6300/test.mp4
    mkdir -p /data/mntc

    mount -t sharefs /data/c /data/mntc -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntc/"

    ./dectool --cmd forced_prefix --path "/data/mntc/currentUser6300/appdata"

    ./dectool --cmd set --tokenid 6300 --path "/data/mntc/currentUser6300" --mode 2 --expect true

    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 1 --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 2 --expect true
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 3 --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 1 --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 2 --expect true
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 3 --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/el2/test.mp4" --mode 1  --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/el2/test.mp4" --mode 2  --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/el2/test.mp4" --mode 3  --expect false

	./dectool --cmd read --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/test.mp4" --mode 2 --expect true

	./dectool --cmd read --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/Desktop/test.mp4" --mode 2 --expect true

    ./dectool --cmd read --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --expect false
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 2 --expect false

    ./dectool --cmd set --tokenid 6300 --path "/data/mntc/currentUser6300/appdata" --mode 2 --expect true

    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 1  --expect false
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 2  --expect true
    ./dectool --cmd check --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 3  --expect false

    ./dectool --cmd read --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --expect false
    ./dectool --cmd write --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 0 --expect true
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 1 --expect false
	./dectool --cmd access --tokenid 6300 --path "/data/mntc/currentUser6300/appdata/test.mp4" --mode 2 --expect true

    ./dectool  --cmd destroy --tokenid 6300 

    umount /data/mntc/ -l
}

#读写创建删除文件
function 6400(){
    rm -rf /data/d
    mkdir -p /data/d/currentUser6400/appdata
    mkdir -p /data/d/currentUser6400/Desktop
    touch /data/d/currentUser6400/appdata/test.mp4
    touch /data/d/currentUser6400/Desktop/test.mp4
    touch /data/d/currentUser6400/test.mp4
    mkdir -p /data/mntd

    mount -t sharefs /data/d /data/mntd -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mntd/"

    ./dectool --cmd forced_prefix --path "/data/mntd/currentUser6400/appdata"

    ./dectool --cmd set --tokenid 6400 --path "/data/mntd/currentUser6400" --mode 3 --expect true

    ./dectool --cmd check --tokenid 6400 --path "/data/mntd/currentUser6400/test.mp4" --mode 3 --expect true

    ./dectool --cmd set --tokenid 6400 --path "/data/mntd/currentUser6400/appdata" --mode 3 --expect true

    ./dectool --cmd check --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --mode 3  --expect true

    ./dectool --cmd read --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --expect true
	
	./dectool --cmd copy --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --dstpath "/data/d/currentUser6400/Desktop/newtest.mp4" --expect true

    ./dectool --cmd copy --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --dstpath "/data/d/currentUser6400/test.mp4" --expect true

    ./dectool --cmd mkdir --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/dir2/test.txt" --expect true

    ./dectool --cmd mkdir --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/dir1/dir12" --expect true

    ./dectool --cmd rename --tokenid 6400 --path "/data/mntd/currentUser6400/appdata/test.mp4" --expect true

    ./dectool --cmd rename --tokenid 6400 --path "/data/mntd/currentUser6400/test.mp4" --expect true

    ./dectool --cmd remove --tokenid 6400 --path "/data/d/currentUser6400/Desktop/newtest.mp4" --expect true

    ./dectool --cmd remove --tokenid 6400 --path "/data/mntd/currentUser6400/Desktop/test.mp4" --expect true


    ./dectool  --cmd destroy --tokenid 6400 

    umount /data/mntd/ -l
}

#设置权限后，rename测试
function 6500(){
    rm -rf /data/a6500
    rm -rf /data/mnta6500
    mkdir -p /data/a6500/b/c

    touch /data/a6500/test.mp4
    touch /data/a6500/b/test.mp4
    touch /data/a6500/b/c/test.mp4
    touch /data/a6500/b/c/test2.mp4

    mkdir -p /data/mnta6500

    mount -t sharefs /data/a6500 /data/mnta6500 -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mnta6500/"

    # /data/mnta6500 被管控，无法rename
    ./dectool --cmd rename --tokenid 6500 --path "/data/mnta6500/test.mp4" --expect false

    ./dectool --cmd rename --tokenid 6500 --path "/data/mnta6500/b/c/test.mp4" --expect false

    ./dectool --cmd set --tokenid 6500 --path "/data/mnta6500/b" --mode 3 --persist true --expect true

    # /data/mnta6500/test.mp4 被管控，无法rename
    ./dectool --cmd rename2 --tokenid 6500 --path "/data/mnta6500/test.mp4" --dstpath  "/data/mnta6500/b/bnewtest.mp4" --expect false

    # 目标目录被管控，无法rename
    ./dectool --cmd rename2 --tokenid 6500 --path "/data/mnta6500/b/test.mp4" --dstpath  "/data/mnta6500/anewtest.mp4" --expect false

    # 源目录跟目标目录均有权限，rename成功
    ./dectool --cmd rename2 --tokenid 6500 --path "/data/mnta6500/b/test.mp4" --dstpath  "/data/mnta6500/b/c/cnewtest.mp4" --expect true

    ./dectool  --cmd destroy --tokenid 6500 

    umount /data/mnta6500/ -l
}

#设置权限后，remove测试
function 6600(){
    mkdir -p /data/a6600/b/c

    touch /data/a6600/test.mp4
    touch /data/a6600/test1.mp4
    touch /data/a6600/test2.mp4
    touch /data/a6600/b/c/test.mp4
    touch /data/a6600/b/c/test2.mp4
    touch /data/a6600/b/c/test3.mp4

    mkdir -p /data/mnta6600

    mount -t sharefs /data/a6600 /data/mnta6600 -o override_support_delete -o user_id=100

    cd /data

    ./dectool --cmd constraint --path "/data/mnta6600/"

    # /mnta6600 为挂载点，删除被拦截，符合预期
    ./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/test.mp4" --expect false

    ./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/b/c/test.mp4" --expect false
	
	./dectool --cmd set --tokenid 6600 --path "/data/mnta6600" --mode 3 --persist true --expect true
	
	./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/test1.mp4" --expect true

    ./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/b/c/test3.mp4" --expect true
	
	./dectool --cmd set --tokenid 6600 --path "/data/mnta6600" --mode 1 --persist true --expect true
	
	./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/test2.mp4" --expect true
	
	./dectool --cmd remove --tokenid 6600 --path "/data/mnta6600/b/c/test2.mp4" --expect true

    umount /data/mnta6600/ -l
	rm -rf /data/a6600
}

#sharefs挂载-重复挂载后进行文件操作
function 6700(){
    rm -rf /data/d
    mkdir -p /data/d/currentUser6700/appdata
    mkdir -p /data/d/currentUser6700/Desktop
    touch /data/d/currentUser6700/appdata/test.mp4
    touch /data/d/currentUser6700/Desktop/test.mp4
    touch /data/d/currentUser6700/test.mp4
    mkdir -p /data/mntd

    mount -t sharefs /data/d /data/mntd -o override_support_delete -o user_id=100
    mount -t sharefs /data/d /data/mntd -o override_support_delete -o user_id=100
    mount -t sharefs /data/d /data/mntd -o override_support_delete -o user_id=100

    cd /data
    ./dectool --cmd constraint --path "/data/mntd/"

    ./dectool --cmd forced_prefix --path "/data/mntd/currentUser6700/appdata"

    ./dectool --cmd set --tokenid 6700 --path "/data/mntd/currentUser6700" --mode 3 --expect true
    ./dectool --cmd check --tokenid 6700 --path "/data/mntd/currentUser6700/test.mp4" --mode 3 --expect true

    ./dectool --cmd set --tokenid 6700 --path "/data/mntd/currentUser6700/appdata" --mode 3 --expect true
    ./dectool --cmd check --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --mode 3  --expect true

    ./dectool --cmd read --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --expect true
    ./dectool --cmd write --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --expect true
	
	./dectool --cmd copy --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --dstpath "/data/d/currentUser6700/Desktop/newtest.mp4" --expect true
    ./dectool --cmd copy --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --dstpath "/data/d/currentUser6700/test.mp4" --expect true

    ./dectool --cmd mkdir --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/dir2/test.txt" --expect true
    ./dectool --cmd mkdir --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/dir1/dir12" --expect true

    ./dectool --cmd rename --tokenid 6700 --path "/data/mntd/currentUser6700/appdata/test.mp4" --expect true
    ./dectool --cmd rename --tokenid 6700 --path "/data/mntd/currentUser6700/test.mp4" --expect true

    ./dectool --cmd remove --tokenid 6700 --path "/data/d/currentUser6700/Desktop/newtest.mp4" --expect true
    ./dectool --cmd remove --tokenid 6700 --path "/data/mntd/currentUser6700/Desktop/test.mp4" --expect true


    ./dectool  --cmd destroy --tokenid 6700 

    umount /data/mntd/ -l
	rm -rf /data/d
}

trap cleanup ERR
echo "Start"
PS4='+${LINENO}: '

0100
0200
0300
0400
0600
0700
0800
0900
1000
1100
1200
1300
1400
1500
1700
1900
1910
1920
2000
2100
2200
2300
2400
2500
2600
2700
2800
2900
3000
3100
3300
3400
3500
3600
3700
3800
3900
4900
5000
5400
5500
5600
5800
5900
6000
6100
6200
6300
6400
6500
6600
6700

echo "All tests passed!"
