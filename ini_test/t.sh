#!/bin/bash
cd sample/
ls -1 . | parallel --gnu "cat {1} | tshark -E separator=/ -E header=yes -Tfields -e frame.time -e ip.src -e ip.dst -r {1}"
