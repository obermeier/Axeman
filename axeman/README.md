AXEMAN_CA_BUNDLE=~/axeman-ca/bundle.pem axeman

## Get root cert

curl -o subca.crt http://nuc-cdp.digital.gov.ru/cdp/subca_ssl_rsa2024.crt
# Convert DER → PEM and inspect:
openssl x509 -in subca.crt -inform DER -out subca.pem
openssl x509 -in subca.pem -noout -subject -issuer -ext authorityInfoAccess



openssl s_client -connect 25.ctlog.digital.gov.ru:443 -showcerts