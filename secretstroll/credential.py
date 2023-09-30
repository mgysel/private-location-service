"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple, Dict, Union

from serialization import jsonpickle

import hashlib
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.native.pairing import G1Element
from petrelic.bn import Bn
import inspect

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = List[Union[type(G1.generator), Bn]]
PublicKey = List[Union[type(G1.generator), type(G2.generator)]]
Signature = Tuple[type(G1.generator), type(G1.generator)]
Attribute = Union[str, Tuple[int, Bn]]
AttributeMap = Dict[str, Tuple[int, Bn]]
Proof = List[Union[Bn, Tuple[int, Bn]]]
IssueRequest = Tuple[type(G1.generator), Proof]
BlindSignature = Tuple[Tuple[type(G1.generator), type(G1.generator)], AttributeMap]
AnonymousCredential = BlindSignature
DisclosureProof = Tuple[Signature, Proof]
t = G1.order().random()

######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    sk = []
    pk = []
    
    x = G1.order().random()
    g = G1.generator()

    gTilde = G2.generator()
    bigX = g ** x
    bigXTilde = gTilde ** x

    sk.append(x)
    sk.append(bigX)

    for i in range(len(attributes)):
        smallY = G1.order().random()
        sk.append(smallY)
    
    pk.append(g)
    for i in range(2):
        if(i == 1):
            pk.append(gTilde)
            pk.append(bigXTilde)

        for j in range(len(attributes)):
            if(i == 0):
                bigY = g ** sk[j+2]
                pk.append(bigY)
            else:
                bigYTilde = gTilde ** sk[j+2]
                pk.append(bigYTilde)
    return (sk, pk)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    if(len(sk) != (len(msgs)+2)):
        raise Exception("Invalid message size")

    x = sk[0]
    ySum = 0
    msgs_byte_sum = b""
    for i in range(len(msgs)):
        ySum += sk[i+2]*Bn.from_binary(msgs[i])
        msgs_byte_sum += msgs[i]

    h = G1.hash_to_point(msgs_byte_sum)
    hWithExp = h ** (x+ySum)

    return (h, hWithExp)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """

    if(signature[0] == G1.unity()):
        return False
    
    gTildeIndex = 0
    while(pk[gTildeIndex] != G2.generator()):
        gTildeIndex += 1

    bigXTilde = pk[gTildeIndex+1]
    bigYTildeMult = bigXTilde
    for i in range(len(msgs)):
        bigYTilde = pk[gTildeIndex+2+i]
        bigYTildeMult *= bigYTilde ** Bn.from_binary(msgs[i])

    gTilde = pk[gTildeIndex]
    return signature[0].pair(bigYTildeMult) == signature[1].pair(gTilde)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """

    g = pk[0]
    # t declared globally to be used in the `obtain_credential` function
    gExpT = g ** t

    yMult = G1.unity()
    yraisMult = G1.unity()
    rais = []
    for attribute in user_attributes.values():
        yMult *= (pk[1 + attribute[0]] ** attribute[1])
        
        rai = G1.order().random()
        yraisMult *= (pk[1 + attribute[0]] ** rai)
        rais.append(rai)

    C = gExpT * yMult

    #Proof
    rt = G1.order().random()
    gExpRT = g ** rt
    R = gExpRT * yraisMult

    toBeHashed = b""
    for i in range(len(pk)):
        toBeHashed += pk[i].to_binary()
    
    toBeHashed += C.to_binary()
    toBeHashed += R.to_binary()

    # c = Hash(g || Y1 || ... || Yi || g_tilde ||Y_tilde1 || ... || Y_tildei || com || R)
    c = Bn(int(hashlib.sha256(toBeHashed).hexdigest(), 16))

    st = (rt - c*t) % G1.order()
    sais = []
    raisIndex = 0
    for attribute in user_attributes.values():
        sai = (rais[raisIndex] - c*attribute[1]) % G1.order()
        sais.append((attribute[0], sai))
        raisIndex += 1

    # Pass the indexes of the hidden attributes in the proof to avoid the server from having to compute them
    # while preserving the association between public key value and attribute
    # pi = [c, st, (index1,sa1), ..., (indexi,sai)]
    proof = [c, st] + sais
    
    return (C, proof)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """

    #Verify proof
    com = request[0]
    proof = request[1]
    c = proof[0]
    g = pk[0]
    rt = proof[1]
    R_prime = (com**c) * (g**rt)

    for i in range(2, len(proof)):
        sai_pk_index = 1 + proof[i][0]
        sai_value = proof[i][1]
        R_prime *= (pk[sai_pk_index]** sai_value)

    toBeHashed = b""
    for i in range(len(pk)):
        toBeHashed += pk[i].to_binary()
    
    toBeHashed += com.to_binary()
    toBeHashed += R_prime.to_binary()

    # c' = Hash(g || Y1 || ... || Yi || g_tilde ||Y_tilde1 || ... || Y_tildei || com || R')
    c_prime = Bn(int(hashlib.sha256(toBeHashed).hexdigest(), 16))

    # Abort if proof is not correct (c != c') 
    if(c != c_prime):
        raise Exception("Incorrect issue request proof.\nAborting")

    u = G1.order().random()
    gExpU = g ** u

    bigX = sk[1]

    yMult = G1.unity()

    for attribute in issuer_attributes.values():
        yMult *= (pk[1+attribute[0]] ** attribute[1])

    rightSide = ((bigX * com * yMult) ** u)

    return ((gExpU, rightSide), issuer_attributes)


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    
    signature = response[0]
    issuerAttributes = response[1]

    rightSideFinalSignature = signature[1]/(signature[0]**t)
    finalSignature = (signature[0], rightSideFinalSignature)
    return (finalSignature, issuerAttributes)


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """

    r = G1.order().random()
    t2 = G1.order().random()

    signature = credential[0]
    attributes = credential[1]

    sigma1ExpR = signature[0]**r
    sigma1ExpT = signature[0]**t2

    randomizedSignature = (sigma1ExpR, (signature[1]*sigma1ExpT)**r)

    # Proof
    rt = G1.order().random()
    gTildeIndex = 0
    while(pk[gTildeIndex] != G2.generator()):
        gTildeIndex += 1
    gTilde = pk[gTildeIndex]
    pairSigma1PrimeGTildeExpRt = (randomizedSignature[0].pair(gTilde)) ** rt
    
    rahis = []
    pairSigma1PrimeYTildeExpRahiMult = GT.unity()
    for i in range(len(hidden_attributes)):
        yTildeIndex = hidden_attributes[i][0]
        yTildei = pk[gTildeIndex + 2 + yTildeIndex]
        rahi = G1.order().random()
        pairSigma1PrimeYTildeExpRahiMult *= (randomizedSignature[0].pair(yTildei)) ** rahi
        rahis.append(rahi)

    R = pairSigma1PrimeGTildeExpRt * pairSigma1PrimeYTildeExpRahiMult

    toBeHashed = b""
    for i in range(len(pk)):
        toBeHashed += pk[i].to_binary()
    
    toBeHashed += randomizedSignature[0].to_binary()
    toBeHashed += randomizedSignature[1].to_binary()
    toBeHashed += R.to_binary()
    toBeHashed += message

    # c = Hash(g || Y1 || ... || Yi || g_tilde ||Y_tilde1 || ... || Y_tildei || signature || R || m)
    c = Bn(int(hashlib.sha256(toBeHashed).hexdigest(), 16))

    st = (rt - c*t2) % G1.order()
    sahis = []
    rahiIndex = 0
    for hidden_attribute in hidden_attributes:
        sahi = (rahis[rahiIndex] - c*hidden_attribute[1]) % G1.order()
        sahis.append((hidden_attribute[0], sahi))
        rahiIndex += 1

    # Pass the indexes of the hidden attributes in the proof to avoid the server from having to compute them
    # while preserving the association between public key value and attribute
    # pi = [c, st, (index1,sah1), ..., (indexi,sahi)]
    proof = [c, st] + sahis

    return (randomizedSignature, proof)

def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        disclosed_attributes: List[Attribute],
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    
    randomizedSignature = disclosure_proof[0]
    proof = disclosure_proof[1]

    if(randomizedSignature[0] == G1.unity()):
        return False

    # Verify proof
    gTildeIndex = 0
    while(pk[gTildeIndex] != G2.generator()):
        gTildeIndex += 1

    gTilde = pk[gTildeIndex]
    pairSigma2PrimeGTilde = randomizedSignature[1].pair(gTilde)

    pairSigma1PrimeYTildeExpAdiMult = GT.unity()

    for disclosed_attribute in disclosed_attributes:
        pairSigma1PrimeYTildeExpAdiMult *= randomizedSignature[0].pair(pk[gTildeIndex + 2 + disclosed_attribute[0]]) ** (-disclosed_attribute[1])


    bigXTilde = pk[gTildeIndex+1]
    pairSigma1PrimeBigXTilde = randomizedSignature[0].pair(bigXTilde)

    leftSide = pairSigma2PrimeGTilde * pairSigma1PrimeYTildeExpAdiMult / pairSigma1PrimeBigXTilde

    c = proof[0]
    R_prime = (leftSide**c) * ((randomizedSignature[0].pair(pk[gTildeIndex]))**proof[1])
        
    for i in range(2, len(proof)):
        hidden_index = proof[i][0]
        sahi = proof[i][1]
        R_prime *= ((randomizedSignature[0].pair(pk[gTildeIndex+2+hidden_index]))**sahi)

    toBeHashed = b""
    for i in range(len(pk)):
        toBeHashed += pk[i].to_binary()
    
    toBeHashed += randomizedSignature[0].to_binary()
    toBeHashed += randomizedSignature[1].to_binary()
    toBeHashed += R_prime.to_binary()
    toBeHashed += message

    # c' = Hash(g || Y1 || ... || Yi || g_tilde ||Y_tilde1 || ... || Y_tildei || signature || R' || m)
    c_prime = Bn(int(hashlib.sha256(toBeHashed).hexdigest(), 16))

    # Abort if proof is not correct (c != c') 
    if(c != c_prime):
        return False

    return True