from credential import *
from client import *
from client import main as client_main
import pytest
import time
import statistics
import random
import string
from stroll import Server, Client

# Tests the 
import numpy as np
import pandas as pd
import io
from contextlib import redirect_stdout

# queries.csv: location queries issued by simulated users
# (IP address, lat, lng, timestamp, POI type filter)
# queries_df = pd.read_csv('privacy_evaluation/queries.csv', sep=' ')
queries_df = pd.read_csv('privacy_evaluation/perturbed_queries.csv', sep=' ')

def parse_responses(responses):
    '''
    Parses string responses to string with just names
    '''
    response_parsed = []
    responses = responses.split('\n')
    for response in responses:
        if '"' in response:
            response_parsed.append(response.split('"')[1])

    return '/'.join(response_parsed)

def query_responses():
    responses = []
    for i, row in queries_df.iterrows():
        lat = str(row['lat'])
        lng = str(row['lon'])
        poi_type = row['poi_type_query']
        args = ['loc', lat, lng, '-T', poi_type]
        
        # Get pk, register
        client_main(['get-pk'])
        client_main(['register', '-u', 'name', '-S', poi_type])

        # Obtain loc responses
        f = io.StringIO()
        with redirect_stdout(f):
            client_main(args)
        response = f.getvalue()
        parsed_response = parse_responses(response)
        print(parsed_response)

        responses.append(parsed_response)
    
    return responses

responses = query_responses()

queries_df['response'] = responses
queries_df.to_csv('privacy_evaluation/perturbed_queries_responses.csv')

# lat = str(46.540782352683166)
# lng = str(6.5918965877586055)
# poi_type = 'restaurant'
# args = ['loc', lat, lng, '-T', poi_type]

# client_main(['get-pk'])
# client_main(['register', '-u', 'name', '-S', poi_type])
# client_main(args)