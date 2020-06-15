#!/usr/bin/env sh

url=https://uploooadit.oooverflow.io/files/
guid='00000000-0229-0101-1231-000000000000'

echo -n 'input: '
read input

curl -X POST -H 'Content-Type: text/plain' -H "X-guid: $guid" --data $input $url
curl ${url}${guid}
