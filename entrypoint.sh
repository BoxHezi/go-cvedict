#!/bin/sh
/go/cvedict --address=${MONGO_HOST} --port=${MONGO_PORT} fetch
/go/cvedict --address=${MONGO_HOST} --port=${MONGO_PORT} server --notifer=${NOTIFIER_URL}