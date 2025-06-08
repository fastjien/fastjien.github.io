#!/bin/bash
#
# Brief description of your script
# Copyright 2025 fastjien

# Globals:
# Arguments:
#  None
function main() {
  # --drafts For the local test, diskpla the contents in the draft directory.
  bundle exec jekyll serve --drafts
}

main "$@"
