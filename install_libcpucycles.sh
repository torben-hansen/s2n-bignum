#!/bin/bash

LIBCRYLE_FOLDER="libcpucycles-20240114"

cd ${LIBCRYLE_FOLDER}
./configure && make -j8 install