from credential import *
from stroll import Server, Client
import pytest

#####################################################################
####              Generic Signing Functions Testing              ####
#####################################################################

def test_success_signature_scheme():
    '''
    Tests successful run of
        - Creating a key pair
        - Signing a message
        - Verifying the signature
    '''
    attributes = ["username"]
    (sk, pk) = generate_key(attributes)
    msg = [b"A"]
    signature = sign(sk, msg)
    assert verify(pk, signature, msg) == True

def test_wrong_pk_signature_scheme():
    '''
    Tests failure run of
        - Creating a key pair
        - Signing a message
        x Verifying the signature with the wrong public key
    '''
    attributes = ["username"]
    (old_sk, old_pk) = generate_key(attributes)
    (sk, pk) = generate_key(attributes)
    msg = [b"A"]
    signature = sign(old_sk, msg)
    assert verify(pk, signature, msg) == False

def test_wrong_size_to_be_signed_signature_scheme():
    '''
    Tests failure run of
        - Creating a key pair
        x Signing a message with size different from secret key
    '''
    attributes = ["username"]
    (sk, pk) = generate_key(attributes)
    msg = [b"A",b"B"]
    with pytest.raises(Exception):
        signature = sign(sk, msg)

def test_wrong_original_msg_to_be_verified_signature_scheme():
    '''
    Tests failure run of
        - Creating a key pair
        - Signing a message
        x Verifying the signature with a different message
    '''
    attributes = ["username"]
    (sk, pk) = generate_key(attributes)
    msg = [b"A"]
    signature = sign(sk, msg)
    msg2 = [b"a"]
    assert verify(pk, signature, msg2) == False

#####################################################################
####                 Credential Functions Testing                ####
#####################################################################

def test_success_credential():
    '''
    Tests successful run of
        - Creating server's key pair
        - Creating issue request
        - Signing the issue request
        - Obtain credential
        - Creating disclosure proof
        - Verifying the disclosure proof
    '''
    valid_subscriptions = ["restaurant", "bar", "sushi", "username"]
    username = "your_name"
    (server_sk, server_pk) = generate_key(valid_subscriptions)

    user_attributes_map = {}
    user_attributes_map[username] = (3, Bn.from_binary(str.encode(username)))

    issuance_request = create_issue_request(server_pk, user_attributes_map)

    valid_subs_list = []
    valid_subscriptions_fd = open("valid_subscriptions.txt", "r")
    for valid_subscription in valid_subscriptions_fd:
        valid_subs_list.append(valid_subscription.replace("\n",""))

    subscriptions = ["restaurant", "bar", "sushi"]
    issuer_attributes_map = {}
    for subscription in subscriptions:
        if(subscription not in valid_subs_list):
            raise Exception("Invalid subscription.\nAborting")
        issuer_attributes_map[subscription] = (valid_subs_list.index(subscription), Bn.from_binary(str.encode(subscription)))

    blind_signature = sign_issue_request(server_sk, server_pk, issuance_request, issuer_attributes_map)

    credential = obtain_credential(server_pk, blind_signature)

    hidden_attributes = [(3, Bn.from_binary(str.encode("your_name")))]
    message = b"46.52345,6.5789"
    signature = create_disclosure_proof(server_pk, credential, hidden_attributes, message)

    revealed_attributes = [(0,Bn.from_binary(str.encode("restaurant"))), (1,Bn.from_binary(str.encode("bar"))), (2,Bn.from_binary(str.encode("sushi")))]
    assert verify_disclosure_proof(server_pk, signature, revealed_attributes, message) == True

def test_not_owned_subscription_in_credential():
    '''
    Tests failure run of
        - Creating server's key pair
        - Creating issue request
        - Signing the issue request
        - Obtain credential
        - Creating disclosure proof
        x Verifying the disclosure proof fails since the user does not have the sushi subscription
    '''
    valid_subscriptions = ["restaurant", "bar", "sushi", "username"]
    username = "your_name"
    (server_sk, server_pk) = generate_key(valid_subscriptions)

    user_attributes_map = {}
    user_attributes_map[username] = (3, Bn.from_binary(str.encode(username)))

    issuance_request = create_issue_request(server_pk, user_attributes_map)

    valid_subs_list = []
    valid_subscriptions_fd = open("valid_subscriptions.txt", "r")
    for valid_subscription in valid_subscriptions_fd:
        valid_subs_list.append(valid_subscription.replace("\n",""))

    subscriptions = ["restaurant", "bar"]
    issuer_attributes_map = {}
    for subscription in subscriptions:
        if(subscription not in valid_subs_list):
            raise Exception("Invalid subscription.\nAborting")
        issuer_attributes_map[subscription] = (valid_subs_list.index(subscription), Bn.from_binary(str.encode(subscription)))

    blind_signature = sign_issue_request(server_sk, server_pk, issuance_request, issuer_attributes_map)

    credential = obtain_credential(server_pk, blind_signature)

    hidden_attributes = [(3, Bn.from_binary(str.encode("your_name")))]
    message = b"46.52345,6.5789"
    signature = create_disclosure_proof(server_pk, credential, hidden_attributes, message)

    revealed_attributes = [(0,Bn.from_binary(str.encode("restaurant"))), (1,Bn.from_binary(str.encode("bar"))), (2,Bn.from_binary(str.encode("sushi")))]
    assert verify_disclosure_proof(server_pk, signature, revealed_attributes, message) == False

def test_modified_message_credential():
    '''
    Tests failure run of
        - Creating server's key pair
        - Creating issue request
        - Signing the issue request
        - Obtain credential
        - Creating disclosure proof
        x Verifying the disclosure proof fails since the user message with their location was changed
    '''
    valid_subscriptions = ["restaurant", "bar", "sushi", "username"]
    username = "your_name"
    (server_sk, server_pk) = generate_key(valid_subscriptions)

    user_attributes_map = {}
    user_attributes_map[username] = (3, Bn.from_binary(str.encode(username)))

    issuance_request = create_issue_request(server_pk, user_attributes_map)

    valid_subs_list = []
    valid_subscriptions_fd = open("valid_subscriptions.txt", "r")
    for valid_subscription in valid_subscriptions_fd:
        valid_subs_list.append(valid_subscription.replace("\n",""))

    subscriptions = ["restaurant", "bar", "sushi"]
    issuer_attributes_map = {}
    for subscription in subscriptions:
        if(subscription not in valid_subs_list):
            raise Exception("Invalid subscription.\nAborting")
        issuer_attributes_map[subscription] = (valid_subs_list.index(subscription), Bn.from_binary(str.encode(subscription)))

    blind_signature = sign_issue_request(server_sk, server_pk, issuance_request, issuer_attributes_map)

    credential = obtain_credential(server_pk, blind_signature)

    hidden_attributes = [(3, Bn.from_binary(str.encode("your_name")))]
    message = b"46.52345,6.5789"
    signature = create_disclosure_proof(server_pk, credential, hidden_attributes, message)
    
    modified_message = b"46.52344,6.5788"
    revealed_attributes = [(0,Bn.from_binary(str.encode("restaurant"))), (1,Bn.from_binary(str.encode("bar"))), (2,Bn.from_binary(str.encode("sushi")))]
    assert verify_disclosure_proof(server_pk, signature, revealed_attributes, modified_message) == False


#####################################################################
####                   Stroll Functions Testing                  ####
#####################################################################

def test_success_run():
    '''
    Tests successful run of 
        - Retrieving the server public key
        - Registering with the server
        - loc command
    '''
    server = Server()
    client = Client()

    valid_subscriptions = ["restaurant", "bar", "sushi", "username"]
    username = "username"
    subscriptions = ["restaurant", "bar", "sushi"]

    (server_sk, server_pk) = server.generate_ca(valid_subscriptions)
    issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
    server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
    credential = client.process_registration_response(server_pk, server_response, private_state)

    message = b"46.52345,6.5789"
    types = ["restaurant", "bar"]
    signature = client.sign_request(server_pk, credential, message, types)

    assert server.check_request_signature(server_pk, message, types, signature) == True

def test_wrong_pk_signature_scheme():
    '''
    Tests failure run of 
        - Retrieving the server public key
        x Registering with the wrong server's public key
    '''
    server = Server()
    client = Client()

    username = "username"
    subscriptions = ["restaurant", "bar", "sushi"]

    (server_sk_old, server_pk_old) = server.generate_ca(subscriptions)
    (server_sk, server_pk) = server.generate_ca(subscriptions)
    
    issuance_request, private_state = client.prepare_registration(server_pk_old, username, subscriptions)

    # Server processing registration should fail as public key is incorrect
    with pytest.raises(Exception):
        server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)

def test_wrong_original_msg_to_be_verified_signature_scheme():
    '''
    Tests failure run of 
        - Retrieving the server public key
        - Registering with the server
        x loc command but verifying with a different message
    '''
    server = Server()
    client = Client()

    username = "username"
    subscriptions = ["restaurant", "bar", "sushi"]

    (server_sk, server_pk) = server.generate_ca(subscriptions)
    issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
    server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
    credential = client.process_registration_response(server_pk, server_response, private_state)

    message = b"46.52345,6.5789"
    types = ["restaurant", "bar"]
    signature = client.sign_request(server_pk, credential, message, types)

    # Message changed
    message = b"46.52344,6.5788"
    assert server.check_request_signature(server_pk, message, types, signature) == False

def test_not_owned_subscription():
    '''
    Tests failure run of 
        - Retrieving the server public key
        - Registering with the server
        x loc command asking for a subscription not owned by the user
    '''
    server = Server()
    client = Client()

    username = "username"
    subscriptions = ["restaurant", "bar", "sushi"]

    (server_sk, server_pk) = server.generate_ca(subscriptions)
    # User does not have sushi subscription
    subscriptions = ["restaurant", "bar"]
    issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
    server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
    credential = client.process_registration_response(server_pk, server_response, private_state)

    message = b"46.52345,6.5789"
    # User asks for subscription he/she does not own
    types = ["restaurant", "bar", "sushi"]
    signature = client.sign_request(server_pk, credential, message, types)

    assert server.check_request_signature(server_pk, message, types, signature) == False

def test_invalid_subscription():
    '''
    Tests failure run of 
        - Retrieving the server public key
        - Registering with the server
        x loc command asking for a subscription not valid to the server
    '''
    server = Server()
    client = Client()

    username = "username"
    subscriptions = ["restaurant", "bar", "sushi"]

    (server_sk, server_pk) = server.generate_ca(subscriptions)
    issuance_request, private_state = client.prepare_registration(server_pk, username, subscriptions)
    server_response = server.process_registration(server_sk, server_pk, issuance_request, username, subscriptions)
    credential = client.process_registration_response(server_pk, server_response, private_state)

    message = b"46.52345,6.5789"
    # Add an invalid subscription
    types = ["restaurant", "bar", "dojo"]
    signature = client.sign_request(server_pk, credential, message, types)

    with pytest.raises(Exception):
        server.check_request_signature(server_pk, message, types, signature)
