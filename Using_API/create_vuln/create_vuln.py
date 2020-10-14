# -*- coding: utf-8 -*-
import csv
import sys
import json
import click
import tempfile
from requests import Session

@click.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
@click.option('--server_address', prompt=True, help='Faraday server url', default='http://localhost:5985')
@click.option('--workspace', prompt=True)
@click.option('--vuln-name', prompt=True)
@click.option('--description', prompt=True)
@click.option('--target-type', prompt=True, type=click.Choice(choices=["Host","Service"]))
@click.option('--target-id', prompt=True, type=int)
def create_vuln(username, password, server_address, workspace, vuln_name, description,target_type,target_id):    
    data = data_to_json(username, workspace, vuln_name, description, target_type, target_id)    
    print('Try to log in to {0} server'.format(server_address))
    session = log_in_faraday(username, password, server_address)
    send_data(session, data, server_address)

def data_to_json(username, workspace, vuln_name, description, target_type, target_id):
    # Collecting the data in a dict
    data = {
		"obj_id":"",
		"owner":username,
		"parent": target_id,
		"parent_type": target_type,
		"type":"Vulnerability",
		"ws":workspace,
		"confirmed":True,
		"data":"",
		"desc":description,
		"easeofresolution":None,
		"impact":{
			"accountability":False,
			"availability":False,
			"confidentiality":False,
			"integrity":False
			},
		"name":vuln_name,
		"owned":False,
		"policyviolations":[],
		"refs":[],
		"resolution":"",
		"severity":"unclassified",
		"issuetracker":"",
		"status":"opened",
		"custom_fields":{},
		"external_id":"",
		"_attachments":{},
		"description":description,
		"protocol":"",
		"version":""
	}
    return data

def log_in_faraday(username, password, server_address):
    # POST HTTP Method, authenticating to faraday server
    session = Session()
    response = session.post(server_address + '/_api/login', json={'email': username, 'password': password})
    assert response.status_code == 200, "Server response with unexpected HTTP error, retry with other credentials"
    return session

def send_data(session, data, server_address):
    response = session.post(server_address + '/_api/v2/ws/{}/vulns/'.format(data['ws']), json=data)

if __name__ == "__main__":
    create_vuln()

