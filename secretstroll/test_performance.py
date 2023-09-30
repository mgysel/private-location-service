from credential import *
from client import *
from client import main as client_main
import pytest
import time
import statistics
import random
import string
from stroll import Server, Client

# Used to test the communication and computation cost in 
# - key generation
# - issuance
# - showing the credential
# - verifying the credential

############################################################################
########################### HELPER FUNCTIONS ###############################
############################################################################

def create_subscriptions(num_subscriptions):
    '''
    Helper function that creates user and issuer attributes
    Inputs
        Number of subscriptions
    Outputs
        subscriptions array
    '''
    subscriptions = []
    valid_subscriptions = ['restaurant', 'bar', 'sushi', 'pizza', 'dojo', 'burritos', 'nightclub', 'indian', 'barbeque', 'salads']
    
    for i in range(num_subscriptions):
        subscriptions.append(valid_subscriptions[i])

    return subscriptions

def create_user_attributes():
    gTildeIndex = 0
    while(server_pk[gTildeIndex] != G2.generator()):
        gTildeIndex += 1

    user_attributes_map = {}
    # -2 instead of -1 because for all the attributes it is made an 
    # adjustment to take into consideration the g in the server pk
    user_attributes_map[username] = (gTildeIndex-2, Bn.from_binary(str.encode(username)))

def create_message(message_length):
    '''
    Helper function used to create binary message of message_length
    '''
    message = bytes(''.join(random.choice(string.ascii_letters) for i in range(message_length)), encoding='utf-8')
    return message

############################################################################
######################### COMPUTATION TESTING ##############################
############################################################################

def test_computation_key_generation(num_subscriptions, num_trials):
    '''
    Tests the computation cost of key generation
    Inputs
        num_subscriptions: Number of subscriptions used for key generation
        num_trials: Number of trials used for testing
    Outputs
        mean and standard deviation
    '''
    print("**********")
    print(f'Number of Subscriptions: {num_subscriptions}')
    print(f'Number of Trials: {num_trials}')

    subscriptions_og = create_subscriptions(num_subscriptions)
    
    results = []
    for i in range(num_trials):
        subscriptions = subscriptions_og.copy()

        start = time.time()
        (sk, pk) = generate_key(subscriptions)
        end = time.time()

        elapsed_time = end - start 
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

    print("Computation Cost of Key Generation: ")
    print(f'Mean: {mean}')
    print(f'Standard Deviation: {std_dev}')

test_computation_key_generation(5, 100)
# test_computation_key_generation(10, 1000)
# test_computation_key_generation(20, 1000)


def test_computation_issuance(num_subscriptions, num_trials):
    '''
    Tests the computation cost of credential issuance
    Inputs
        num_subscriptions: Number of subscriptions used for key generation
        num_trials: Number of trials used for testing
    Outputs
        mean and standard deviation
    '''
    print("***************************************")
    print(f'Number of User Subscriptions: {num_subscriptions}')
    print(f'Number of Trials: {num_trials}')
    
    subscriptions_og = create_subscriptions(num_subscriptions)
    
    results = []
    for i in range(num_trials):
        server = Server()
        client = Client()

        username = 'username'
        subscriptions = subscriptions_og.copy()

        (server_sk, server_pk) = server.generate_ca(subscriptions)

        start = time.time()
        issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
        server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
        credential = client.process_registration_response(server_pk, server_response, private_state)
        end = time.time()

        elapsed_time = end - start 
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

    print("Computation Cost of Issuance: ")
    print(f'Mean: {mean}')
    print(f'Standard Deviation: {std_dev}')

test_computation_issuance(5, 10)
# test_computation_issuance(10, 10, 1000)
# test_computation_issuance(20, 20, 1000)



def test_computation_showing(num_subscriptions, num_trials):
    '''
    Tests the computation cost of showing the credential (sign_request)
    Inputs
        num_subscriptions: Number of subscriptions used for key generation
        num_trials: Number of trials used for testing
    Outputs
        mean and standard deviation
    '''
    print("***************************************")
    print(f'Number of User Subscriptions: {num_subscriptions}')
    print(f'Number of Trials: {num_trials}')
    
    subscriptions_og = create_subscriptions(num_subscriptions)
    
    results = []
    for i in range(num_trials):
        server = Server()
        client = Client()

        username = 'username'
        subscriptions = subscriptions_og.copy()

        (server_sk, server_pk) = server.generate_ca(subscriptions)
        issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
        server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
        credential = client.process_registration_response(server_pk, server_response, private_state)

        message = b'46.52345,6.5789'
        types = subscriptions_og.copy()
        
        start = time.time()
        signature = client.sign_request(server_pk, credential, message, types)
        end = time.time()

        elapsed_time = end - start 
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

    print("Computation Cost of Showing: ")
    print(f'Mean: {mean}')
    print(f'Standard Deviation: {std_dev}')

test_computation_showing(5, 10)
# test_computation_showing(10, 10, 1000)
# test_computation_showing(20, 20, 1000)




def test_computation_verification(num_subscriptions, num_trials):
    '''
    Tests the computation cost of verifying the credential
    Inputs
        num_subscriptions: Number of subscriptions used for key generation
        num_trials: Number of trials used for testing
    Outputs
        mean and standard deviation
    '''
    print("***************************************")
    print(f'Number of User Subscriptions: {num_subscriptions}')
    print(f'Number of Trials: {num_trials}')
    
    subscriptions_og = create_subscriptions(num_subscriptions)
    
    results = []
    for i in range(num_trials):
        server = Server()
        client = Client()

        username = 'username'
        subscriptions = subscriptions_og.copy()

        (server_sk, server_pk) = server.generate_ca(subscriptions)
        issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
        server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
        credential = client.process_registration_response(server_pk, server_response, private_state)

        message = b'46.52345,6.5789'
        types = subscriptions_og.copy()
        signature = client.sign_request(server_pk, credential, message, types)
        
        start = time.time()
        server.check_request_signature(server_pk, message, types, signature)
        end = time.time()

        elapsed_time = end - start 
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

    print("Computation Cost of Verification: ")
    print(f'Mean: {mean}')
    print(f'Standard Deviation: {std_dev}')

test_computation_verification(5, 10)
# test_computation_verification(10, 10, 1000)
# test_computation_verification(20, 20, 1000)





############################################################################
######################## COMMUNICATION TESTING #############################
############################################################################

def test_communication_get_pk(num_trials):
    '''
    Tests the communication cost of client get-pk, 
    which retrieves the public key from the server
    Inputs
        n
    Outputs
        mean and standard deviation
    '''
    results = []
    for i in range(num_trials):
        start = time.time()
        client_main(['get-pk'])
        end = time.time()
        elapsed_time = end - start
        results.append(elapsed_time)
    
    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

    print("Computation Cost of Verification Protocol: ")
    print(f'Mean: {mean}')
    print(f'Standard Deviation: {std_dev}')

    print(end - start)

test_communication_get_pk(10)

def get_pois(num_poi):
    '''
    Helper function used to return argument used for register command
    Inputs
        num_poi: number of pois
    Output
        arg used in register command
    '''
    # TODO: GET ALL POIs FROM DATABASE
    poi = ['restaurant', 'bar', 'dojo']
    return poi[0:num_poi]


def test_communication_register(num_trials, num_poi):
    '''
    Tests the communication cost of client register, 
    which registers points of interest
    Inputs
        n
    Outputs
        mean and standard deviation
    '''
    poi = get_pois(num_poi)
    args = ['register', '-u', 'name']
    for i in range(num_poi):
        args.append('-S')
        args.append(poi[i])

    results = []
    for i in range(num_trials):
        client_main(['get-pk'])

        start = time.time()
        client_main(args)
        end = time.time()
        elapsed_time = end - start
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)

test_communication_register(10, 2)


def test_communication_loc(num_trials, num_poi):
    '''
    Tests the communication cost of client loc, 
    which retrieves info about pois
    Inputs
        n
    Outputs
        mean and standard deviation
    '''
    results = []
    for i in range(num_trials):
        poi = get_pois(num_poi)
        args = ['loc']
        lat = str(random.uniform(46.5, 46.57))
        lng = str(random.uniform(6.55, 6.65))
        args.append(lat)
        args.append(lng)
        for i in range(num_poi):
            args.append('-T')
            args.append(poi[i])

        client_main(['get-pk'])

        start = time.time()
        client_main(args)
        end = time.time()
        elapsed_time = end - start
        results.append(elapsed_time)

    mean = statistics.mean(results)
    std_dev = statistics.stdev(results)
    
test_communication_loc(10, 2)
