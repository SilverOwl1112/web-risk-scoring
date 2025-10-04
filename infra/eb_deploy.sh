#!/bin/bash
eb init -p docker web-risk-scoring
eb create web-risk-scoring-env
eb deploy
