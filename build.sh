#!/usr/bin/env bash

SWD="$(realpath ${BASH_SOURCE%/*})"

main(){
  printf "Ensuring build directory...\n"
  mkdir -p "${SWD}/build"
  printf "Tidying...\n"
  go mod tidy
  printf "Building...\n"
  if go build -o "${SWD}/build/nocloud-init" "${SWD}/main.go"; then
    printf "Done. Compiled as %s/build/nocloud-init\n" "${SWD}"
  else
    printf "Error\n"
    exit 1
  fi
}
main "$@"
