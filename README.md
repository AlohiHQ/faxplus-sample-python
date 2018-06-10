# Faxplus api sample python app

This sample app is build to get you started using [faxplus-api](https://github.com/faxplus/faxplus-python) SDK. It contains sample code to get access_token and use refresh token to renew access_token. It also contains sample requests to all endpoints and a GUI to view responses easily.

## Requirements.

- Python 2.7 and 3.4+
- A fax.plus account with activated API

## Installation & Usage

- sample app runs on localhost:8080. so you need to add http://localhost:8080/cb/ to your redirect uris in fax.plus website.
- run following commands to install requirements and create a config.json file

```sh
cd sample-app
pip install -r requirements.txt
cp sample.config.json config.json
```
- edit config.json add your client_id and secret
- run `python app.py` to run sample app.
