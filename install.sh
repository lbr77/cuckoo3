#!/bin/bash

pip install -U wheel
pip install -U requests
# TMP solution until new versions of sflock etc are released to PyPI
pip install -U git+https://github.com/cert-ee/peepdf
pip install -U git+https://github.com/cert-ee/sflock
ROACH_DIR="./roach"
if ! [[ -d "$ROACH_DIR/.git" ]]; then
  git clone https://github.com/cert-ee/roach "$ROACH_DIR"
fi
if [[ -f "$ROACH_DIR/setup.py" ]]; then
  perl -0pi -e "s/capstone-windows==3.0.4/capstone-windows==5.0.4/g" "$ROACH_DIR/setup.py"
  perl -0pi -e "s/capstone==3.0.5/capstone==5.0.5/g" "$ROACH_DIR/setup.py"
fi
pip install -U "$ROACH_DIR"
pip install -U git+https://github.com/cert-ee/httpreplay

declare -a pkglist=("./common" "./processing" "./machineries" "./web" "./node" "./core")

for pkg in ${pkglist[@]}
do
  if ! [[ -d "$pkg" ]]; then
    echo "Missing package: $pkg"
    exit 1
  fi

  pip install -e "$pkg"
  if [ $? -ne 0 ]; then
      echo "Install of $pkg failed"
      exit 1
  fi
done
