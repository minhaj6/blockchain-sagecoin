# Author: Minhaj SixByte


#### ------ create a blockchain structure ------ ####

import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse

class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof = 1, previous_hash = '0')
        self.nodes = set()

    def create_block(self, proof, previous_hash):
        block = {'index' : len(self.chain) + 1,
                 'timestamp' : str(datetime.datetime.now()),
                 'proof' : proof,
                 'previous_hash' : previous_hash,
                 'transactions' : self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == "0000":
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1 
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:4] != '0000':
                return False
        
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({'sender' : sender,
                                'receiver' : receiver,
                                'amount' : amount})
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1 

    def add_node(self, address):
        url = urlparse(address)
        self.nodes.add(url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True

##### ---------- Flask app ---------- ####
app = Flask(__name__)

node_address = str(uuid4()).replace('-', '')


bc = Blockchain()
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    previous_block = bc.get_previous_block()
    previous_proof = previous_block['proof']
    proof = bc.proof_of_work(previous_proof)
    previous_hash = bc.hash(previous_block)
    block = bc.create_block(proof, previous_hash)
    bc.add_transaction(sender = node_address, receiver= 'Akib', amount= 1)
    response = {'message': 'successfully mined a block.',
                'index' : block['index'],
                'proof' : block['proof'],
                'previous_hash' : block['previous_hash'],
                'transactions' : block['transactions']}
    return jsonify(response), 200

@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain' : bc.chain,
                'length' : len(bc.chain)}
    return jsonify(response), 200

@app.route('/validity_check', methods = ['GET'])
def check_validity():
    is_valid = bc.is_chain_valid(bc.chain)
    if is_valid:
        response = {"message" : "Blockchain validity check passed."}
    else:
        response = {"message" : "Blockchain validity check failed!"}
    return jsonify(response), 200

@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some keys/fields of the transaction is missing.', 400
    index = bc.add_transaction(json['sender'], json['receiver'], json['amount'])
    response = {'message' : f'This transaction will be added to block {index}'}
    return jsonify(response), 201

@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node found", 400
    for node in nodes:
        bc.add_node(node)
    response = {'message' : "All the nodes are connected. Nodes are printed below.",
                'total_nodes' : list(bc.nodes)}
    return jsonify(response), 200

@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = bc.replace_chain()
    if is_chain_replaced:
        response = {"message" : "Chain was replaced by the longest chain",
                    "new_chain" : bc.chain}
    else:
        response = {"message" : "Chain is up to date and therefore not replaced.",
                    "chain" : bc.chain}
    return jsonify(response), 200

# running the flask app
app.run(host = '0.0.0.0', port = 5001)
