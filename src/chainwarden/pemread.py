"""PEM reading: split a text buffer into labelled base64 blocks and decode.

A PEM block looks like:

    -----BEGIN CERTIFICATE-----
    <base64>
    -----END CERTIFICATE-----
