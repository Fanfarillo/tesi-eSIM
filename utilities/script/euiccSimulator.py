import base64, json, socket, ssl, sslkeylog

from http import client
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, tag, univ



#DEFINIZIONE DI CLASSI PYTHON PER I CAMPI ASN.1 DEI MESSAGGI

"""
EUICCInfo1 ::= [32] SEQUENCE {                                                          --tag BF20 
  svn [2] VersionType (3 bytes OctetString),                                            --tag 82
  euiccCiPKIdListForVerification [9] SEQUENCE OF SubjectKeyIdentifier (OctetString),    --tag A9
  euiccCiPKIdListForSigning [10] SEQUENCE OF SubjectKeyIdentifier (OctetString)         --tag AA
}
"""

class VersionType(univ.OctetString):    #it must be three bytes
  pass    #pass = non sto aggiungendo nulla rispetto alla classe parent (univ.Integer)

class SubjectKeyIdentifier(univ.OctetString):
  pass    #pass = non sto aggiungendo nulla rispetto alla classe parent (univ.OctetString)

class EUICCInfo1(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('svn', VersionType().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('euiccCiPKIdListForVerification', univ.SequenceOf(componentType=SubjectKeyIdentifier()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('euiccCiPKIdListForSigning', univ.SequenceOf(componentType=SubjectKeyIdentifier()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)))
  )



"""
ServerSigned1 ::= SEQUENCE {                        --tag 30
  transactionId [0] TransactionId (OctetString),    --tag 80
  euiccChallenge [1] Octet16 (16 bytes Integer),    --tag 81
  serverAddress [3] UTF8String,                     --tag 83
  serverChallenge [4] Octet16 (16 bytes Integer)    --tag 84
}
"""

class TransactionId(univ.OctetString):
  pass

class ServerSigned1(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('transactionId', TransactionId().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('euiccChallenge', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('serverAddress', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('serverChallenge', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)))
  )



"""
AuthenticateServerResponse ::= [56] CHOICE {            --tag BF38
  authenticateResponseOk AuthenticateResponseOk,
  authenticateResponseError AuthenticateResponseError
}

AuthenticateResponseOk ::= SEQUENCE {                   --tag 30
  euiccSigned1 EuiccSigned1,
  euiccSignature1 [APPLICATION 55] OCTET STRING,        --tag 5F37
  euiccCertificate Certificate,
  eumCertificate Certificate
}

AuthenticateResponseError ::= SEQUENCE {                --tag 30
  transactionId [0] TransactionId,                      --tag 80
  authenticateErrorCode AuthenticateErrorCode
}

EuiccSigned1 ::= SEQUENCE {                             --tag 30
  transactionId [0] TransactionId,
  serverAddress [3] UTF8String,
  serverChallenge [4] Octet16 (16 bytes Integer),
  euiccInfo2 [34] EuiccInfo2,
  ctxParams1 CtxParams1
}
"""



#questa è una funzione ausiliaria che serve a estrarre il campo VALUE da una tripla <TYPE, LENGTH, VALUE> di un elemento ASN.1.
def extract_asn_value(tlv, lentag=1):
  tagdigits = 2*lentag                        #ciascun byte viene chiaramente espresso con due cifre

  length_hex = tlv[tagdigits : tagdigits+2]   #primo byte subito dopo il TAG
  length = int(length_hex, base=16)           #valore del primo byte subito dopo il TAG
  lenlen = length - 128
  #caso in cui il primo byte subito dopo il TAG vale più di 128 (0x80) --> LENGTH è composto da 1 byte indicante il numero di byte usati per esprimere la lunghezza di VALUE + i byte usati per esprimere la lunghezza di VALUE
  if lenlen > 0:
    length_hex = tlv[2+tagdigits : 2+tagdigits+(2*lenlen)]  #2+tagdigits == byte successivo a lenlen; 2+tagdigits+(2*lenlen) == byte successivo a LENGTH
    length = int(length_hex, base=16)
  #caso in cui il primo byte subito dopo il TAG vale al più (0x80) --> LENGTH è composto da 1 unico byte indicante la lunghezza di VALUE
  else:
    lenlen = 0

  lendigits = 2*length
  lenlendigits = 2*lenlen

  value = tlv[2+tagdigits+lenlendigits : 2+tagdigits+lenlendigits+lendigits]  #2+tagdigits+lenlendigits == byte successivo a LENGTH; 2+tagdigits+lenlendigits+lendigits == fine stringa
  return value



def open_connection(hostname, portnum):
  #TCP socket creation
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  conn = client.HTTPSConnection(hostname, portnum, context=context)

  #esecuzione dell'handshake TLS "mano a mano"
  tls_socket = context.wrap_socket(sock, server_hostname=hostname)
  tls_socket.connect((hostname, portnum))
  conn.sock = tls_socket
  return conn



def send_msg1(conn):
  #crea un'istanza dell'oggetto EUICCInfo1
  euiccInfo1_asn = EUICCInfo1().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 32))
  #imposta i valori dei campi [SET]
  euiccInfo1_asn['svn'] = b'\x02\x02\x02' #it must be three bytes
  euiccInfo1_asn['euiccCiPKIdListForVerification'].extend([b'\x81\x37\x0F\x51\x25\xD0\xB1\xD4\x08\xD4\xC3\xB2\x32\xE6\xD2\x5E\x79\x5B\xEB\xFB', b'\x18\x1B\xF2\x59\x4C\xC2\xE1\x11\xFF\xA3\xF6\x88\x6E\x10\x11\x32\x12\xEC\x4E\x41'])
  euiccInfo1_asn['euiccCiPKIdListForSigning'].extend([b'\x81\x37\x0F\x51\x25\xD0\xB1\xD4\x08\xD4\xC3\xB2\x32\xE6\xD2\x5E\x79\x5B\xEB\xFB', b'\x18\x1B\xF2\x59\x4C\xC2\xE1\x11\xFF\xA3\xF6\x88\x6E\x10\x11\x32\x12\xEC\x4E\x41'])
  #codifica l'oggetto EUICCInfo1 in DER
  euiccInfo1_der = encoder.encode(euiccInfo1_asn)
  #codifica il DER in base64
  byte_euiccInfo1 = base64.b64encode(euiccInfo1_der)

  #imposta il valore di euiccChallenge [SET]
  val_euiccChallenge = 232645733703218863597835671721642336624
  bit_length = 16*8   #it's an Octet16
  #here's where the magic happens
  byte_val_euiccChallenge = val_euiccChallenge.to_bytes((bit_length + 7) // 8, byteorder="big")
  #codifica il valore di euiccChallenge in base64
  byte_euiccChallenge = base64.b64encode(byte_val_euiccChallenge)

  #json fields for msg 1
  euiccInfo1 = byte_euiccInfo1.decode()
  smdpAddress = "sys.prod.ondemandconnectivity.com"   #[SET]
  euiccChallenge = byte_euiccChallenge.decode()

  #dictionary for msg 1
  dict_msg1 = {
    "euiccInfo1": euiccInfo1,
    "smdpAddress": smdpAddress,
    "euiccChallenge": euiccChallenge
  }
  print("[initiateAuthentication - SENT]")
  print(dict_msg1, "\n")

  #convert into json for msg 1
  msg1 = json.dumps(dict_msg1)
  #definition of header HTTPS [SET]
  hdr1 = {'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'gsma-rsp-com.truphone.lpad', 'X-Admin-Protocol': 'gsma/rsp/v2.2.0', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip'}

  #sending message to the server
  conn.request('POST', '/gsma/rsp2/es9plus/initiateAuthentication', msg1, hdr1)
  #receiving response from the server
  response1 = conn.getresponse()

  #extracting header of server response
  hdr_response1 = response1.getheaders()
  print("[initiateAuthenticationResponse - RECEIVED]")
  print(hdr_response1, "\n")

  #extracting body message of server response
  str_response1 = response1.read().decode()
  #converting body message in json
  dict_response1 = json.loads(str_response1)
  print(dict_response1, "\n")
  return dict_response1



def send_msg2(conn, dict_response1):
  #transactionId: è sufficiente estrarlo dalla risposta del server al messaggio precedente.
  transactionId = dict_response1['transactionId']

  #serverSigned1: è necessario estrarlo dalla risposta del server e convertirlo in ASN.1 per ottenere i relativi campi.
  serverSigned1 = dict_response1['serverSigned1']
  serverSigned1_der = base64.b64decode(serverSigned1)                                 #decodifica l'oggetto base64 in DER
  serverSigned1_asn = decoder.decode(serverSigned1_der, asn1Spec=ServerSigned1())     #decodifica l'oggetto DER in ASN.1
  #di serverSigned1_asn servono i campi transactionId, serverAddress e serverChallenge
  serverSigned1_transactionId_der = encoder.encode(serverSigned1_asn[0][0])           #qui si ha la tripla <TYPE, LENGTH, VALUE> - bisogna estrarre VALUE e portarlo in uppercase
  serverSigned1_transactionId = extract_asn_value(serverSigned1_transactionId_der.hex()).upper()
  serverSigned1_serverAddress = serverSigned1_asn[0][2]
  serverSigned1_serverChallenge = serverSigned1_asn[0][3]

  #euiccCiPKIdToBeUsed: è necessario estrarlo dalla risposta del server e convertirlo in ASN.1 per ottenere l'id della chiave pubblica che deve essere utilizzata.
  euiccCiPKIdToBeUsed = dict_response1['euiccCiPKIdToBeUsed']
  euiccCiPKIdToBeUsed_der = base64.b64decode(euiccCiPKIdToBeUsed)   #decodifica l'oggetto base64 in DER - bisogna estrarre VALUE e portarlo in uppercase
  euiccCiPKIdToBeUsed_field = extract_asn_value(euiccCiPKIdToBeUsed_der.hex()).upper()

  #serverSignature1 e serverCertificate non servono per costruire il messaggio successivo da inviare al server, bensì solo per autenticare il server (passaggio omesso).

  print("transactionId = ", transactionId)
  print("serverSigned1_transactionId = ", serverSigned1_transactionId)
  print("serverSigned1_serverAddress = ", serverSigned1_serverAddress)
  print("serverSigned1_serverChallenge = ", serverSigned1_serverChallenge)
  print("euiccCiPKIdToBeUsed_field = ", euiccCiPKIdToBeUsed_field)

  #TODO: costruire la specifica ASN.1 del campo authenticateServerResponse del nuovo messaggio da inviare al server. Poi generare i certificati che inizializzeranno alcune sottosezioni di authenticateServerResponse.

  return None



if __name__ == "__main__":
  #inizializzazione delle variabili per la connessione col server [SET]
  hostname = "sys.prod.ondemandconnectivity.com"
  portnum = 443

  sslkeylog.set_keylog("keylog.log")                #creazione del file di log che manterrà le informazioni sulla master key di TLS
  conn = open_connection(hostname, portnum)         #apertura della connessione TLS con il server
  dict_response1 = send_msg1(conn)                  #preparazione e invio del messaggio initiateAuthentication
  dict_response2 = send_msg2(conn, dict_response1)  #parsing della risposta del server e preparazione e invio del messaggio authenticateClient
