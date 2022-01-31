#!/bin/bash
FILES=$(grep -v "#" files_minigeth_inc_modified_added)
MINIGETH=$PWD/minigeth3
rm -rf $MINIGETH
cd go-ethereum
rsync -R --ignore-missing-args $FILES $MINIGETH
cd -

git diff --no-index --name-status minigeth3 minigeth \
    | grep "^M" \
    | xargs -d'\n' -I {} sh -c "echo {} | cut -c 13-" \ # modified files start with "minigeth3"
    > minigeth3_modified_files

git diff --no-index --name-status minigeth3 minigeth \
    | grep "^A" \
    | xargs -d'\n' -I {} sh -c "echo {} | cut -c 12-" \ # added files start with "minigeth"
    > minigeth3_added_files

git diff --no-index --name-status minigeth3 minigeth \
    | grep "^M" \
    | xargs -d'\n' -I {} sh -c "echo {} | cut -c 13-" \
    | xargs -d'\n' -I {} sh -c "git diff --no-index minigeth3/{} minigeth/{} | cat" \
    > minigeth3_diff_modified
