
### Put your repo root folder path here !!!! ###
ROOT_FOLDER=""
cd $ROOT_FOLDER || exit

# The list of words to search and replace
# Note: it searches exactly for words but not text occurrences
# so for the word "foo" it will find it in "foo > 2" or "x.foo = 1" text but will not
# find anything in "fool > 2"
OCCURENCE_AND_REPLACE_FEED=(
  "firstWordToSearchForReplacement"   "theWordToReplaceTheFirstWord"
  "secondWordToSearchForReplacement"   "theWordToReplaceTheSecondWord"
  "..."   "..."
);

# This is a list of files (file pathes relative to the root folder) and their regex adjustments.
# The regex adjustment we need to put before the words we search.
# For example:
# For the adjustment "\." and word to search "foo" the search will
# find ".foo" in "someCircuitName.foo" text but will not find anythin in "var x=foo"
# for the adjustment "" it will find the word "foo" anywhere
FILES_AND_REGEX_TO_PROCESS=(
  "circuits/lib/idOwnershipBySignature.circom"  " " # will find "x.input1 <== foo" but not "x.foo"
  "circuits/lib/query/credentialAtomicQueryMTP.circom"  "\." # will find "x.foo" but not "x.input1 <== foo"
  "circuits/lib/authentication.circom"  "\."
  "test/idOwnership/idOwnershipBySignature.test.ts"  "" # will find "foo" word in any place
  "test/circuits/idOwnershipBySignature.circom"  ""
);

OCCURENCE_AND_REPLACE_FEED_LENGTH=${#OCCURENCE_AND_REPLACE_FEED}

for i in $(seq 1 2 $OCCURENCE_AND_REPLACE_FEED_LENGTH);
do
  next_i=$((i+1))
  OCCURRENCE_TO_REPLACE=${OCCURENCE_AND_REPLACE_FEED[$i]}
  NEW_OCCURRENCE=${OCCURENCE_AND_REPLACE_FEED[$next_i]}

  for m in $(seq 1 2 ${#FILES_AND_REGEX_TO_PROCESS});
  do
    next_m=$((m+1))
    FILE_PATH=$ROOT_FOLDER${FILES_AND_REGEX_TO_PROCESS[$m]}
    REGEX_ADJUSTMENT=${FILES_AND_REGEX_TO_PROCESS[$m+1]}
    sed -i'.bak' "s/"$REGEX_ADJUSTMENT"[[:<:]]"$OCCURRENCE_TO_REPLACE"[[:>:]]/"$REGEX_ADJUSTMENT$NEW_OCCURRENCE"/g" $FILE_PATH
    rm $FILE_PATH".bak"
  done
done

git status
#git checkout HEAD ./circuits/**/*.circom ./test/circuits/**/*.circom ./test/**/*.test.ts

