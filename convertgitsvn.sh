#!/bin/sh -x

project=$1

git remote add $project /workspace/rc-legacy/$project-git

git fetch $project

git merge -s ours --no-commit --allow-unrelated-histories $project/master

git read-tree --prefix=$project -u $project/master

git commit -a -m "Merge remote-tracking branch '$project/master'"
