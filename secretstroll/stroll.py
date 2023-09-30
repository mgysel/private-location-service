"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from serialization import jsonpickle
from credential import *

# Type aliases
State = Dict[str, Tuple[int, Bn]]


class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        pass

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        valid_subscriptions_fd = open("valid_subscriptions.txt", "w")
        for subscription in subscriptions:
            valid_subscriptions_fd.write(subscription+"\n")
        valid_subscriptions_fd.flush()
        valid_subscriptions_fd.close()

        # We add a secret key that only the user would know to the credential
        (server_sk, server_pk) = generate_key(subscriptions + ["secretkey"])
        server_sk_bytes, server_pk_bytes = str.encode(jsonpickle.encode(server_sk)), str.encode(jsonpickle.encode(server_pk))
        return (server_sk_bytes, server_pk_bytes)

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            server_pk: the server's public key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """

        valid_subs_list = []
        valid_subscriptions_fd = open("valid_subscriptions.txt", "r")
        for valid_subscription in valid_subscriptions_fd:
            valid_subs_list.append(valid_subscription.replace("\n",""))

        for subscription in subscriptions:
            if(subscription not in valid_subs_list):
                raise Exception("Invalid subscription.\nAborting")

        server_sk = jsonpickle.loads(server_sk)
        server_pk = jsonpickle.loads(server_pk)
        issuance_request = jsonpickle.loads(issuance_request)

        issuer_attributes_map = {}
        for valid_subscription in valid_subs_list:
            if(valid_subscription in subscriptions):
                value = Bn(1)
            elif(valid_subscription == "username"):
                value = Bn.from_binary(str.encode(username))
            else:
                value = Bn(0)

            issuer_attributes_map[valid_subscription] = (valid_subs_list.index(valid_subscription), value)

        blind_signature = sign_issue_request(server_sk, server_pk, issuance_request, issuer_attributes_map)
        return jsonpickle.encode(blind_signature)


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        
        server_pk = jsonpickle.loads(server_pk)
        signature = jsonpickle.loads(signature)

        valid_subs_list = []
        valid_subscriptions_fd = open("valid_subscriptions.txt", "r")
        for valid_subscription in valid_subscriptions_fd:
            valid_subs_list.append(valid_subscription.replace("\n",""))
        
        revealed_attributes_list = []
        for attribute in revealed_attributes:
            # Will raise an error if the subscription is not valid, since it
            # will not be in the valid subscriptions list
            if(attribute not in valid_subs_list):
                raise Exception("Invalid subscription.\nAborting")
            revealed_attributes_list.append((valid_subs_list.index(attribute), Bn(1)))

        return verify_disclosure_proof(server_pk, signature, revealed_attributes_list, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        pass

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """

        server_pk = jsonpickle.loads(server_pk)

        user_attributes_map = {}
        client_sk = G1.order().random()

        gTildeIndex = 0
        while(server_pk[gTildeIndex] != G2.generator()):
            gTildeIndex += 1

        # -2 instead of -1 because for all the attributes it is made an 
        # adjustment to take into consideration the g in the server pk
        # and the attribute position in the server's list

        user_attributes_map["clientkey"] = (gTildeIndex - 2, client_sk)

        issuance_request = create_issue_request(server_pk, user_attributes_map)

        # Pass the username as the state
        state = user_attributes_map
        return (jsonpickle.encode(issuance_request), state)


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        server_pk = jsonpickle.loads(server_pk)
        server_response = jsonpickle.loads(server_response)

        credential = obtain_credential(server_pk, server_response)
        credential = list(credential)
        credential[1].update(private_state)
        credential = tuple(credential)
        return str.encode(jsonpickle.encode(credential))


    def sign_request(
            self,
            server_pk: bytes,
            credential: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        
        server_pk = jsonpickle.loads(server_pk)
        credential = jsonpickle.loads(credential)

        hidden_attributes = []
        attributes = credential[1].copy()
        for attribute in attributes.items():
            if(attribute[0] not in types):
                hidden_attributes.append(attribute[1])

        signature = create_disclosure_proof(server_pk, credential, hidden_attributes, message)
        return jsonpickle.encode(signature)
