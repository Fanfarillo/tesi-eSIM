import base64, json, socket, ssl

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, tag, univ


#DEFINIZIONE DI CLASSI PYTHON PER I CAMPI ASN.1 DEI MESSAGGI
"""
EUICCInfo1 ::= [32] SEQUENCE {                                                          --tag BF20 
  svn [2] VersionType (maybe 3 bytes),                                                  --tag 82
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


def open_connection(hostname, portnum):
    #TCP socket creation
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #enabling TLS on the connection
    context = ssl.create_default_context()

    try:
        tls_socket = context.wrap_socket(sock, server_hostname=hostname)
        tls_socket.connect((hostname, portnum))
        return tls_socket

    except ssl.SSLError as e:
        print("Errore durante la connessione TLS: ", e)
        return None
    except socket.error as e:
        print("Errore durante la connessione al server: ", e)
        return None


def send_msg_1(tls_socket, recv_buf_size):
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

  #convert into json for msg 1
  msg1 = json.dumps(dict_msg1)
  print("[initiateAuthentication - SENT]")
  print(msg1)

  #TODO: incapsulare il json in un messaggio HTTPS che contenga anche un header opportuno; dopodiché, inviare il pacchetto e restituire la risposta del server
  return None


if __name__ == "__main__":
  #inizializzazione variabili per la connessione col server [SET]
  hostname = "www.repubblica.it"
  portnum = 443
  recv_buf_size = 65536   #dimensione dei buffer di output in cui verranno riportate le risposte del server

  tls_socket = open_connection(hostname, portnum)
  server_response = send_msg_1(tls_socket, recv_buf_size)   #preparazione e invio del messaggio initiateAuthentication
