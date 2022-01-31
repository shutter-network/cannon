#!/bin/bash
FILES=$(grep -v "#" files_minigeth)
MINIGETH=$PWD/minigeth2
cd go-ethereum
rsync -R $FILES $MINIGETH
cd -
git diff --no-index --name-status minigeth2 minigeth \
    | xargs -d'\n' -I {} sh -c "echo {} | cut -c 12-" \
    > minigeth2_modified_added_files
cat files_minigeth minigeth2_modified_added_files > files_minigeth_inc_modified_added
