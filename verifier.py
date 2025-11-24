myurl='http://localhost:9000'


from flask import *
import os
from fido2.server import *
from fido2.webauthn import *
import base64
from urllib.parse import urlparse
app=Flask(__name__)

app.secret_key=os.urandom(32)

import base64
import json

def serialize_cred(cred):
	cred2={'aaguid': base64.b64encode(cred['aaguid']).decode(), 'credential_id': base64.b64encode(cred['credential_id']).decode()}
	pubkey={}
	for x in cred['public_key']:
		if isinstance(cred['public_key'][x], bytes):
			pubkey[x]='base64_'+base64.b64encode(cred['public_key'][x]).decode()
		else:
			pubkey[x]=cred['public_key'][x]
	cred2['public_key']=pubkey
	return json.dumps(cred2)
    
def deserialize_cred(credjson):
	cred=json.loads(credjson)
	cred['aaguid']=base64.b64decode(cred['aaguid'])
	cred['credential_id']=base64.b64decode(cred['credential_id'])
	cred2={}

	for x in cred['public_key']:
		if not isinstance(cred['public_key'][x], int) and cred['public_key'][x].startswith('base64_'):
			cred2[int(x)]=base64.b64decode(cred['public_key'][x][len('base64_'):])
		else:
			cred2[int(x)]=cred['public_key'][x]
	return AttestedCredentialData.create(aaguid=cred['aaguid'], credential_id=cred['credential_id'], public_key=cred2)
	
import requests
from jose import jws
import json
from datetime import datetime

# Resolve DID Document
def resolve_did(did):
    # Convert did:web to URL (e.g., did:web:localhost:5000 -> http://localhost:5000/.well-known/did.json)
    if not did.startswith("did:web:"):
        raise ValueError("Only did:web is supported")
    domain = did.replace("did:web:", "")
    url = f"https://{domain}/.well-known/did.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        did_doc = response.json()
        
        # Extract public key from DID Document
        for vm in did_doc.get('verificationMethod', []):
            if vm.get('type') == 'EcdsaSecp256r1VerificationKey2019':
                return vm['publicKeyJwk']
        raise ValueError("No suitable public key found in DID Document")
    except Exception as e:
        raise ValueError(f"Failed to resolve DID: {str(e)}")

# Verify Verifiable Credential
def verify_credential(presentation):
    try:
        # Resolve public key from DID Document
        public_key = resolve_did(presentation['issuer'])
        # Extract JWS (Verifiable Credential)
        jws_token = presentation['verifiableCredential']

        # Verify JWS signature
        verified_credential = jws.verify(jws_token, public_key, algorithms=['ES256'])
        credential = json.loads(verified_credential.decode('utf-8'))

        # Validate credential structure
        if not all(key in credential for key in ['@context', 'id', 'type', 'issuer', 'issuanceDate', 'credentialSubject']):
            raise ValueError("Invalid credential structure")

        # Check issuance date
        issuance_date = datetime.fromisoformat(credential['issuanceDate'].replace("Z", "+00:00"))
        if issuance_date > datetime.utcnow():
            raise ValueError("Credential issued in the future")


        print("Credential verified successfully!")
        print(json.dumps(credential, indent=2))
        return credential

    except Exception as e:
        print(f"Verification failed: {str(e)}")
        return None

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify():
	presentation=request.json
	cred=verify_credential(presentation)
	if cred is not None:
		session['cred']=cred
	else:
		if 'cred' in session:
			session.pop('cred')
		return jsonify({'status':False})
	
	resp={'status': cred is not None, 'user': cred['credentialSubject']['user']}
	return jsonify(resp)
	

@app.route('/authenticate/begin')
def register_begin():
	pagex=session['cred']['credentialSubject']['pagex']
	pagex_domain=urlparse(pagex).netloc
	rp = PublicKeyCredentialRpEntity(name="PageX", id=pagex_domain)
	server = Fido2Server(rp)
	options, state = server.authenticate_begin()
	user=session['cred']['credentialSubject']['user']['name']

	print(options.public_key.challenge)

	chalb64=base64.urlsafe_b64encode(options.public_key.challenge).decode()
	session['state']=state
	return redirect(f'{pagex}?challenge={chalb64}&type=get&user_id={user}&callback={myurl}/authenticate/complete')

@app.route('/authenticate/complete')
def register_complete():
	state=session['state']
	pagex=session['cred']['credentialSubject']['pagex']	
	clientDataJson=base64.urlsafe_b64decode(request.args.get('clientDataJSON'))
	authenticatorData=base64.urlsafe_b64decode(request.args.get('authenticatorData'))
	signature=base64.urlsafe_b64decode(request.args.get('signature'))
	authenticatorId=base64.urlsafe_b64decode(request.args.get('authenticatorId'))
	rawId=authenticatorId
	
	respjsonxx={'clientDataJSON': clientDataJson, 'authenticatorData': authenticatorData, 'signature': signature}
	print(respjsonxx)
	resp=AuthenticatorAssertionResponse.from_dict(respjsonxx)
	pagex_domain=urlparse(pagex).netloc
	cred={'rawId': rawId, 'response': resp}
	rp = PublicKeyCredentialRpEntity(name="PageX", id=pagex_domain)
	server = Fido2Server(rp)
	credjson=json.dumps(session['cred']['credentialSubject']['cred'])
	credentials=[deserialize_cred(credjson)]
	print(credentials)
	server.authenticate_complete(state, credentials, cred)
	session['loggedin']=session['cred']['credentialSubject']['user']
	return redirect('/dashboard')
	
@app.route('/dashboard')
def dashboard():
	if 'loggedin' in session and session['loggedin']	 is not None:
		return render_template('dashboard.html', details=json.dumps(session['loggedin']))
	if 'loggedin' in session:
		session.pop('loggedin')
	return redirect('/logout')
		
@app.route('/logout')
def logout():
	if 'loggedin' in session:
		session.pop('loggedin')
	return redirect('/')

			
app.run(host='0.0.0.0', port=9000, debug=True)
