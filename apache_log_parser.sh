#!/bin/bash

input_dir=$1
output_dir="results.txt"
total_files=`find $input_dir -type f | wc -l`

count=1
for file_path in `find $input_dir -type f`; do
        fn=$(basename "$file_path")
        #parent=$(echo $file_path | sed 's/\PATH\/TO\/MNT\///' | sed "s/$fn//")
        echo "[*] [$count/$total_files]"
        echo "[+] Processing: [$count/$total_files]"
        echo "[-] Full Path : $file_path"
        echo "[-] Parent folder : $parent"
        echo "[-] Filename  : $fn"
        cat $file_path | while read line; do
                ip=`echo $line | awk '{print $2}'`
                server=`echo $line | awk -F'"' '{print $12}'`
                ts=`echo $line | awk -F'[' '{print $2}' | awk -F']' '{print $1}'`
                pg=`echo $line | awk '{print $8}'`
                echo $ts','$ip','$server','$pg
        done
        ((count++))
done

